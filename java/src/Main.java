import io.grpc.ManagedChannelBuilder;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NegotiationType;
import io.grpc.netty.NettyChannelBuilder;
import io.grpc.stub.StreamObserver;
import trust.nccgroup.burppipe.EvalRequest;
import trust.nccgroup.burppipe.EvalResponse;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Base64;
import java.util.concurrent.CountDownLatch;
import java.util.stream.Collectors;

class Main {

  public static void main(String[] argv) throws Throwable {
    new Main().run(argv);
  }

  public void run(String[] argv) throws Throwable {
    YoloCertKey server_ca = null;
    YoloCertKey server_leaf = null;

    YoloCertKey client_ca = null;
    YoloCertKey client_leaf = null;

    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);


      server_ca = YoloCertKey.newInstance();
      X509CertificateGenerator server_leafgen = new X509CertificateGenerator(server_ca.cert, (RSAPrivateCrtKey)server_ca.key);
      server_leaf = server_leafgen.createCertificate("localhost", 200);

      client_ca = YoloCertKey.newInstance("Totally Legit Client Cert Root", "Trust me (I'm a CA Cert)");
      X509CertificateGenerator client_leafgen = new X509CertificateGenerator(server_ca.cert, (RSAPrivateCrtKey)server_ca.key);
      client_leaf = client_leafgen.createCertificate("Awesome Client", 200);

      if (argv.length == 0) {
        throw new RuntimeException("yolo");
      }
    } catch (Throwable t) {
      t.printStackTrace();
      return;
    }




    String cert_chain = server_leaf.getCert() + server_ca.getCert();
    String private_key = server_leaf.getKey();
    String client_root = client_ca.getCert();

    String input = Base64.getEncoder().encodeToString(cert_chain.getBytes()) + ":" +
      Base64.getEncoder().encodeToString(private_key.getBytes()) + ":" +
      Base64.getEncoder().encodeToString(client_root.getBytes()) + "\n";

    System.out.print("sent: " + input);

    System.in.read();
    //EvalPipeClient client = new EvalPipeClient("localhost", 50051);

    ManagedChannelBuilder<?> mcb = NettyChannelBuilder.forAddress("127.0.0.1", 50051)
      .sslContext(GrpcSslContexts.forClient()
        .trustManager(server_ca.cert)
        .keyManager(client_leaf.key, client_ca.cert, client_leaf.cert)
        .build()
      )
      /*.negotiationType(NegotiationType.TLS)*/
      ;

    mcb.overrideAuthority("localhost");

    EvalPipeClient client = new EvalPipeClient(mcb);

    Thread.sleep(2000);

    final CountDownLatch finishLatch = new CountDownLatch(1);
    client.asyncStub.evaluate(EvalRequest.newBuilder().setScript(argv[0]).build(), new StreamObserver<EvalResponse>() {
      @Override
      public void onNext(EvalResponse value) {
        System.out.println(value.getJsonData());
        this.onCompleted();
      }

      @Override
      public void onError(Throwable t) {
        t.printStackTrace();
        this.onCompleted();
      }

      @Override
      public void onCompleted() {
        try {
          finishLatch.countDown();
          client.shutdown();
        } catch (Throwable t) {
          t.printStackTrace();
        }
      }
    });

    try {
      finishLatch.await();

      //client_proc.destroy();
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
  }
}
