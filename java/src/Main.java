import io.grpc.stub.StreamObserver;
import trust.nccgroup.burppipe.EvalRequest;
import trust.nccgroup.burppipe.EvalResponse;

import java.util.concurrent.CountDownLatch;

class Main {

  public static void main(String[] argv) {
    new Main().run(argv);
  }

  public void run(String[] argv) {
    EvalPipeClient client = new EvalPipeClient("localhost", 50051);

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
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
  }
}
