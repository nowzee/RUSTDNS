use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use trust_dns_proto::op::{Message, MessageType, OpCode, ResponseCode};
use log::{info, LevelFilter};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::new()
        .filter_level(LevelFilter::Info)
        .init();

    info!("Starting DNS server...");

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 132)), 53);
    let socket = Arc::new(UdpSocket::bind(addr).await?);
    
    info!("DNS server listening on {}", addr);

    loop {
        let mut buf = vec![0; 512];

        let (size, src) = match socket.recv_from(&mut buf).await {
            Ok((size, src)) => (size, src),
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                continue;
            }
        };


        let request_data = buf[..size].to_vec();


        let socket_clone = Arc::clone(&socket);


        tokio::spawn(async move {

            let request = match Message::from_vec(&request_data) {
                Ok(message) => message,
                Err(e) => {
                    eprintln!("Error parsing DNS message: {}", e);
                    return;
                }
            };

            if request.message_type() != MessageType::Query {
                return;
            }
            

            
            for query in request.queries() {
                let domain = str::trim_end_matches(&query.name().to_string(), '.').to_string();
                
                if domain == "example.com" {  // ban a specific domain
                    println!("IP SOURCE: {}", src);
                    println!("Domain blocked : {}", domain);
                } else {
                    let mut response = Message::new();
                    response.set_id(request.id());
                    response.set_message_type(MessageType::Response);
                    response.set_op_code(OpCode::Query);
                    response.set_recursion_desired(request.recursion_desired());
                    response.set_recursion_available(false);
                    response.set_response_code(ResponseCode::NoError);
                    response.add_query(query.clone());

                    let response_data = match response.to_vec() {
                        Ok(data) => data,
                        Err(e) => {
                            eprintln!("Error serializing response: {}", e);
                            return;
                        }
                    };

                    if let Err(e) = socket_clone.send_to(&response_data, src).await {
                        eprintln!("Error sending response: {}", e);
                    }
                }
            }
        });
    }
}
