# Synthetic example only. These .invalid hosts are not live services.
.class public Ldemo/NetworkClient;
.super Ljava/lang/Object;

.field private static final BASE_URL:Ljava/lang/String; = "https://api.example.invalid/v1/"
.field private static final SOCKET_URL:Ljava/lang/String; = "wss://events.example.invalid/stream"
.field private static final BROKER:Ljava/lang/String; = "mqtts://broker.example.invalid:8883"

.method public connect()V
    .locals 2
    const-string v0, "https://api.example.invalid/v1/session"
    const-string v1, "10.24.8.12:8443"
    invoke-static {v0}, Lio/grpc/ManagedChannelBuilder;->forTarget(Ljava/lang/String;)Lio/grpc/ManagedChannelBuilder;
    return-void
.end method

.method public encode()V
    .locals 1
    const-string v0, "demo.telemetry.TelemetryService/SendEvent"
    invoke-virtual {v0}, Lcom/google/protobuf/GeneratedMessageLite;->toByteArray()[B
    return-void
.end method
