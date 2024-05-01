#[tokio::main]
async fn main() {
    // do get request to the server, localhost:3000
    let response = reqwest::get("http://localhost:3000").await.unwrap();
    // print the response
    println!("Status: {}", response.status());
    println!("Headers:\n{:#?}", response.headers());
    println!("Body:\n{}", response.text().await.unwrap());


}