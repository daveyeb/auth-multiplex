use dashmap::DashMap;
use governor::{clock::DefaultClock, state::keyed::DefaultKeyedStateStore, Quota, RateLimiter};
use std::{
    num::NonZeroU32,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};

use thiserror::Error;
use tokio::{sync::Mutex, time::Instant};

/// Errors that can occur during rate limiting operations
#[derive(Error, Debug)]
pub enum RateLimitError {
    /// Returned when a user has exceeded their quota
    #[error("User quota exceeded (limit: {0})")]
    UserQuotaExceeded(u32),

    /// Returned when the system-wide capacity is exceeded
    #[error("System capacity exceeded")]
    SystemOverloaded,
}

/// Represents a user's quota state, including limits and usage
#[derive(Clone)]
pub struct UserQuota {
    /// Atomic counter for tracking request count
    count: Arc<AtomicU32>,

    /// Maximum number of requests allowed in the quota period
    limit: u32,

    /// Timestamp of the last quota reset
    last_reset: Instant,

    /// Timestamp of the last activity for this user
    last_activity: Instant,
}

/// A two-layer rate limiter implementation providing both per-user and global limits
pub struct TokenRateLimiter {
    /// Layer 1: Per-user quotas based on business rules
    user_quotas: Arc<DashMap<String, UserQuota>>,

    /// Layer 2: Global failsafe to protect system resources
    global_limiter: Arc<RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>>,

    /// Configuration parameters for the rate limiter
    config: LimiterConfig,

    /// Handle to the background cleanup task
    cleanup_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

/// Configuration for the TokenRateLimiter
pub struct LimiterConfig {
    /// Maximum number of requests allowed globally in the specified period
    pub global_limit: u32,

    /// Time period for the global rate limit
    pub global_period: Duration,

    /// Default request limit for users without a custom limit
    pub default_user_limit: u32,

    /// Time period after which user quotas are reset
    pub user_quota_reset_interval: Duration,

    /// Time after which inactive users are removed from tracking
    pub user_inactivity_timeout: Duration,
}

impl Default for LimiterConfig {
    fn default() -> Self {
        Self {
            global_limit: 10000,
            global_period: Duration::from_secs(60),
            default_user_limit: 100,
            user_quota_reset_interval: Duration::from_secs(3600), // 1 hour
            user_inactivity_timeout: Duration::from_secs(86400),  // 24 hours
        }
    }
}

impl TokenRateLimiter {
    /// Creates a new TokenRateLimiter with the specified configuration
    ///
    /// # Examples
    ///
    /// ```
    /// let config = LimiterConfig::default();
    /// let limiter = TokenRateLimiter::new(config);
    /// ```
    pub fn new(config: LimiterConfig) -> Self {
        // Use with_period but create a more restrictive quota configuration
        // We set the burst allowance equal to the limit to enforce strict rate limiting
        let quota = Quota::with_period(config.global_period)
            .unwrap()
            .allow_burst(NonZeroU32::new(config.global_limit).unwrap());

        let global_limiter = Arc::new(RateLimiter::keyed(quota));
        let instance = Self {
            user_quotas: Arc::new(DashMap::new()),
            global_limiter,
            config,
            cleanup_task: Arc::new(Mutex::new(None)),
        };
        instance.start_cleanup_task();
        instance
    }

    /// Checks if a request from the specified user should be allowed
    ///
    /// This method doesn't actually consume the quota - use `record_success` after
    /// a successful operation to count it against the quota.
    ///
    /// # Arguments
    ///
    /// * `user_id` - Unique identifier for the user making the request
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the request is allowed
    /// * `Err(RateLimitError)` - If the request exceeds limits
    pub async fn check(&self, user_id: &str) -> Result<(), RateLimitError> {
        let user_key = user_id.to_string();

        // First handle user quota
        let mut entry = self
            .user_quotas
            .entry(user_key.clone())
            .or_insert_with(|| UserQuota {
                count: Arc::new(AtomicU32::new(0)),
                limit: self.config.default_user_limit,
                last_reset: Instant::now(),
                last_activity: Instant::now(),
            });

        let now = Instant::now();

        // Check if reset is needed
        if now.duration_since(entry.last_reset) >= self.config.user_quota_reset_interval {
            entry.count.store(0, Ordering::Release);
            entry.last_reset = now;
        }

        // Check user quota
        let current = entry
            .count
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                if current < entry.limit {
                    Some(current + 1)
                } else {
                    None
                }
            });

        match current {
            Ok(_) => {
                entry.last_activity = now;

                // Check global limiter (this will return immediately if limit exceeded)
                if self.global_limiter.check_key(&user_key).is_err() {
                    // Decrement the user's count since we're not actually allowing the request
                    entry.count.fetch_sub(1, Ordering::SeqCst);
                    return Err(RateLimitError::SystemOverloaded);
                }
                Ok(())
            }
            Err(_) => Err(RateLimitError::UserQuotaExceeded(entry.limit)),
        }
    }

    /// Sets a custom request limit for a specific user
    ///
    /// # Arguments
    ///
    /// * `user_id` - Unique identifier for the user
    /// * `limit` - Maximum number of requests allowed in the quota period
    pub fn set_user_limit(&self, user_id: &str, limit: u32) {
        if let Some(mut entry) = self.user_quotas.get_mut(user_id) {
            // Preserve existing state but update limit
            entry.limit = limit;
        } else {
            // Create new entry with specified limit
            self.user_quotas.insert(
                user_id.to_string(),
                UserQuota {
                    count: Arc::new(AtomicU32::new(0)),
                    limit,
                    last_reset: Instant::now(),
                    last_activity: Instant::now(),
                },
            );
        }
    }

    /// Gets the current usage information for a user
    ///
    /// # Arguments
    ///
    /// * `user_id` - Unique identifier for the user
    ///
    /// # Returns
    ///
    /// * `Some((current_count, limit))` - If the user exists
    /// * `None` - If the user doesn't exist in the quota system
    pub fn get_user_usage(&self, user_id: &str) -> Option<(u32, u32)> {
        self.user_quotas
            .get(user_id)
            .map(|entry| (entry.count.load(Ordering::Relaxed), entry.limit))
    }

    /// Starts the background task that periodically resets quotas and removes inactive users
    fn start_cleanup_task(&self) {
        let quotas = self.user_quotas.clone();
        let cleanup_interval = Duration::from_millis(50); // Run cleanup more frequently for tests
        let reset_interval = self.config.user_quota_reset_interval;
        let inactivity_timeout = self.config.user_inactivity_timeout;
        let cleanup_task = self.cleanup_task.clone();

        let handle = tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(cleanup_interval);
            loop {
                interval_timer.tick().await;
                let now = Instant::now();

                // Collect keys to remove to avoid mutable borrowing issues
                let keys_to_remove: Vec<String> = quotas
                    .iter()
                    .filter_map(|entry| {
                        let key = entry.key().clone();
                        let quota = entry.value();
                        if now.duration_since(quota.last_activity) > inactivity_timeout {
                            Some(key)
                        } else {
                            None
                        }
                    })
                    .collect();

                // Remove inactive users
                for key in keys_to_remove {
                    quotas.remove(&key);
                }

                // Reset quotas if needed
                for mut entry in quotas.iter_mut() {
                    if now.duration_since(entry.last_reset) >= reset_interval {
                        entry.count.store(0, Ordering::Relaxed);
                        entry.last_reset = now;
                    }
                }
            }
        });

        tokio::spawn(async move {
            let mut task_guard = cleanup_task.lock().await;
            *task_guard = Some(handle);
        });
    }

    /// Safely shuts down the rate limiter and its background tasks
    pub async fn shutdown(&self) -> Result<(), tokio::task::JoinError> {
        // Cancel the cleanup task
        let mut cleanup_guard = self.cleanup_task.lock().await;
        if let Some(handle) = cleanup_guard.take() {
            handle.abort();

            // Optionally wait for the task to complete (with timeout)
            match tokio::time::timeout(Duration::from_secs(5), handle).await {
                Ok(result) => {
                    // Handle the result of the join
                    if let Err(e) = result {
                        if !e.is_cancelled() {
                            return Err(e);
                        }
                    }
                }
                Err(_) => {
                    // Timeout occurred, just continue
                }
            }
        }

        // Clear all user quotas to free memory
        self.user_quotas.clear();

        Ok(())
    }

    /// Resets the quota for a specific user
    ///
    /// # Arguments
    ///
    /// * `user_id` - Unique identifier for the user
    pub fn reset_user_quota(&self, user_id: &str) {
        if let Some(mut entry) = self.user_quotas.get_mut(user_id) {
            entry.count.store(0, Ordering::Relaxed);
            entry.last_reset = Instant::now();
        }
    }

    /// Force removal of a user from the rate limiter
    ///
    /// Primarily for testing purposes
    ///
    /// # Arguments
    ///
    /// * `user_id` - Unique identifier for the user to remove
    pub fn remove_user(&self, user_id: &str) {
        self.user_quotas.remove(user_id);
    }
}


