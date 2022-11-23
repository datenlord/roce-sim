use async_rdma::RdmaBuilder;
use portpicker::pick_unused_port;
use std::alloc::Layout;
use std::{
    io,
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};

/// An error occurred in the requester's local channel interface that can be
/// associated with a certain WQE.
///
/// mr and qp belong to different pds
mod rxe_local_qp_operation_error {
    use super::*;
    static LAYOUT: Layout = Layout::new::<[u8; 8]>();

    async fn client(addr: SocketAddrV4) -> io::Result<()> {
        let rdma = RdmaBuilder::default().connect(addr).await?;
        let mut rdma = rdma.set_new_pd()?;
        let mr = rdma.alloc_local_mr(LAYOUT)?;
        // then the `Rdma`s created by `new_connect` will have a new `ProtectionDomain`
        let new_rdma = rdma.new_connect(addr).await?;
        new_rdma.send(&mr).await.unwrap();
        Ok(())
    }

    #[tokio::main]
    async fn server(addr: SocketAddrV4) -> io::Result<()> {
        let mut rdma = RdmaBuilder::default().listen(addr).await?;
        let new_rdma = rdma.listen().await?;
        let _buf = new_rdma.receive().await?;
        Ok(())
    }

    #[should_panic]
    #[tokio::test]
    async fn main() {
        let addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), pick_unused_port().unwrap());
        std::thread::spawn(move || server(addr));
        tokio::time::sleep(Duration::from_secs(1)).await;
        client(addr)
            .await
            .map_err(|err| println!("{}", err))
            .unwrap();
    }
}
