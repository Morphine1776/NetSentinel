using NetSentinel.SimAgent;

var port = 1161;
var trapPort = 1162;
var community = "public";
var sendTrap = true;
var single = false;

for (var i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--port" when i + 1 < args.Length:
            port = int.Parse(args[++i]);
            single = true;
            break;
        case "--trap" when i + 1 < args.Length:
            trapPort = int.Parse(args[++i]);
            break;
        case "--community" when i + 1 < args.Length:
            community = args[++i];
            break;
        case "--single":
            single = true;
            break;
        case "--no-trap":
            sendTrap = false;
            break;
        case "--help":
        case "-h":
            Console.WriteLine("NetSentinel SNMP simulator");
            Console.WriteLine("  default             seven devices on UDP 1161 and 1163-1168");
            Console.WriteLine("  --single            one device, on --port or 1161");
            Console.WriteLine("  --port <udp>        implies --single");
            Console.WriteLine("  --trap <udp>        trap destination (default 1162)");
            Console.WriteLine("  --community <name>  community string (default public)");
            Console.WriteLine("  --no-trap           do not send a startup trap");
            return;
    }
}

var agents = new List<SimSnmpAgent>();
if (single)
{
    agents.Add(new SimSnmpAgent(port, community, SimCatalog.Core));
}
else
{
    foreach (var (listenPort, device) in SimCatalog.DefaultAgents)
    {
        agents.Add(new SimSnmpAgent(listenPort, community, device));
    }
}

foreach (var agent in agents)
{
    agent.Start();
}

Console.WriteLine("NetSentinel SNMP simulator");
Console.WriteLine($"  community {community}");
foreach (var agent in agents)
{
    var silence = agent.Answers ? "" : "  (does not answer)";
    Console.WriteLine($"  {agent.SysName,-14} udp://127.0.0.1:{agent.Port}  {agent.Location}{silence}");
}

Console.WriteLine("  LLDP      core Gi0/0 — dist, core Gi0/1 — access");
Console.WriteLine($"  trap      coldStart from {agents[0].SysName} to 127.0.0.1:{trapPort}");
Console.WriteLine("Ctrl+C to stop.");

using var stopped = new CancellationTokenSource();
Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    stopped.Cancel();
};

if (sendTrap)
{
    var sender = agents[0];
    _ = Task.Run(async () =>
    {
        await Task.Delay(500, stopped.Token);
        try
        {
            sender.SendTrap(trapPort);
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
finally
{
    foreach (var agent in agents)
    {
        agent.Dispose();
    }
}
