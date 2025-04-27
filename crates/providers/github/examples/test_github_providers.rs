use core_lib::OAuthProvider;
use github::GitHubProvider;
use std::io::{self, Write};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let github = GitHubProvider::new(
        "Iv1.2a3f50156283a5de".to_string(),
        "9953eb51a1cc4ab0b9ba7ddf0fbc82e404e203ea".to_string(),
    );

    let auth_url = github.auth_url();
    println!(
        "🔗 Visit this URL in your browser to authenticate:\n{}\n",
        auth_url
    );

    print!("Paste the `code` from the redirect URL: ");
    io::stdout().flush()?; // Force print before input

    let mut code = String::new();
    io::stdin().read_line(&mut code)?;
    let code = code.trim(); // Remove newline

    let token = github.exchange_code(code).await.unwrap();
    println!("\n✅ Access token response: {:#?}", token);

    Ok(())
}
