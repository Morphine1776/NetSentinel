using NetSentinel.SimAgent;

var port = 1161;
var trapPort = 1162;
var community = "public";
var sendTrap = true;

for (var i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--port" when i + 1 < args.Length:
            port = int.Parse(args[++i]);
            break;
        case "--trap" when i + 1 < args.Length:
            trapPort = int.Parse(args[++i]);
            break;
        case "--community" when i + 1 < args.Length:
            community = args[++i];
            break;
        case "--no-trap":
            sendTrap = false;
            break;
        case "--help":
        case "-h":
            Console.WriteLine("NetSentinel SNMP simulator");
            Console.WriteLine("  --port <udp>        agent port (default 1161)");
            Console.WriteLine("  --trap <udp>        trap destination port (default 1162)");
            Console.WriteLine("  --community <name>  community string (default public)");
            Console.WriteLine("  --no-trap           do not send a startup trap");
            return;
    }
}

using var agent = new SimSnmpAgent(port, community);
agent.Start();
Console.WriteLine("NetSentinel SNMP simulator");
Console.WriteLine($"  agent     udp://127.0.0.1:{agent.Port}");
Console.WriteLine($"  community {community}");
Console.WriteLine("  sysName   sim-core-01");
Console.WriteLine("  Gi0/0     100 Mbps simulated inbound");
Console.WriteLine("  Gi0/2     administratively up, operationally down");
Console.WriteLine($"  trap      coldStart to 127.0.0.1:{trapPort}");
Console.WriteLine("Ctrl+C to stop.");

using var stopped = new CancellationTokenSource();
Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    stopped.Cancel();
};

if (sendTrap)
{
    _ = Task.Run(async () =>
    {
        await Task.Delay(500, stopped.Token);
        try
        {
            agent.SendTrap(trapPort);
            Console.WriteLine("Sent coldStart trap.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Trap was not delivered: {ex.Message}");
        }
    }, stopped.Token);
}

try
{
    await Task.Delay(Timeout.Infinite, stopped.Token);
}
catch (OperationCanceledException)
{
    Console.WriteLine("Stopping simulator.");
}
