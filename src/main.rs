use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use trust_dns_proto::op::{Message, MessageType, OpCode, ResponseCode};
use log::{info, LevelFilter};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the logger
    env_logger::Builder::new()
        .filter_level(LevelFilter::Info)
        .init();

    info!("Starting DNS server...");

    // Create a socket address to listen on (UDP port 53 is the standard DNS port)
    // Note: Running on port 53 typically requires admin/root privileges
    // You might want to use a higher port number (e.g., 5353) for testing
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5353);

    // Bind to the address
    let socket = Arc::new(UdpSocket::bind(addr).await?);
    println!("DNS server listening on {}", addr);
    info!("DNS server listening on {}", addr);

    // Main server loop
    loop {
        // Buffer for receiving DNS queries
        let mut buf = vec![0; 512]; // Standard DNS message size

        // Wait for a DNS query
        let (size, src) = match socket.recv_from(&mut buf).await {
            Ok((size, src)) => (size, src),
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                continue;
            }
        };

        // Clone the buffer for this request
        let request_data = buf[..size].to_vec();

        // Clone the Arc to the socket for this request
        let socket_clone = Arc::clone(&socket);

        // Process the request in a separate task
        tokio::spawn(async move {
            // Parse the DNS message
            let request = match Message::from_vec(&request_data) {
                Ok(message) => message,
                Err(e) => {
                    eprintln!("Error parsing DNS message: {}", e);
                    return;
                }
            };

            // Check if it's a query
            if request.message_type() != MessageType::Query {
                return;
            }

            // Print each queried domain name
            for query in request.queries() {
                let domain = query.name().to_string();
                println!("DNS Query: {}", domain);
                info!("DNS Query: {}", domain);
            }

            // Create a response message
            let mut response = Message::new();
            response.set_id(request.id());
            response.set_message_type(MessageType::Response);
            response.set_op_code(OpCode::Query);
            response.set_recursion_desired(request.recursion_desired());
            response.set_recursion_available(false);
            response.set_response_code(ResponseCode::NoError);

            // Add the queries from the request to the response
            for query in request.queries() {
                response.add_query(query.clone());
            }

            // Serialize the response
            let response_data = match response.to_vec() {
                Ok(data) => data,
                Err(e) => {
                    eprintln!("Error serializing response: {}", e);
                    return;
                }
            };

            // Send the response
            if let Err(e) = socket_clone.send_to(&response_data, src).await {
                eprintln!("Error sending response: {}", e);
            }
        });
    }
}
