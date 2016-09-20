import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import trust.nccgroup.burppipe.EvalPipeGrpc;
import trust.nccgroup.burppipe.EvalPipeGrpc.*;

import java.util.concurrent.TimeUnit;

public class EvalPipeClient {

  private final ManagedChannel channel;
  public final EvalPipeBlockingStub blockingStub;
  public final EvalPipeStub asyncStub;

  public EvalPipeClient(String host, int port) {
    this(ManagedChannelBuilder.forAddress(host, port).usePlaintext(true));
  }

  public EvalPipeClient(ManagedChannelBuilder<?> channelBuilder) {
    channel = channelBuilder.build();

    blockingStub = EvalPipeGrpc.newBlockingStub(channel);
    asyncStub = EvalPipeGrpc.newStub(channel);
  }

  public void shutdown() throws InterruptedException {
    channel.shutdown().awaitTermination(5, TimeUnit.SECONDS);
  }

}
