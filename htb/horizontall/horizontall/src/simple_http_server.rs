use std::net;
use std::path::PathBuf;

use tokio::sync::oneshot;
use warp::{Filter};

pub struct SimpleHTTPServer {
    socket_addr: net::SocketAddr,
    dir_path: Option<PathBuf>,
    tx: Option<oneshot::Sender<()>>
}

impl SimpleHTTPServer {
    pub fn new(socket_addr: net::SocketAddr) -> Self {
        SimpleHTTPServer {
            socket_addr,
            dir_path: None,
            tx: None
        }
    }
    
    pub fn serve(&mut self, dir_path: impl Into<PathBuf>) {
        if self.tx.is_none() {
            self.dir_path = Some(dir_path.into().clone());
            let route = warp::any()
                .and(warp::fs::dir(self.dir_path.clone().unwrap()));
            let (tx, rx) = oneshot::channel();
            let (_addr, server) = warp::serve(route)
                .bind_with_graceful_shutdown(self.socket_addr.clone(), async {
                    rx.await.ok();
                });
            tokio::task::spawn(server);
            self.tx = Some(tx);
        }
    }

    pub fn stop(&mut self) {
        if self.tx.is_some() {
            let mut t: Option<oneshot::Sender<()>> = None;
            std::mem::swap(&mut self.tx, &mut t);
            t.unwrap().send(()).unwrap();
        }
        if self.dir_path.is_some() {
            self.dir_path = None;
        }
    }
}
