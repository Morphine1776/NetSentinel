using System.Net;
using System.Net.Sockets;
using System.Diagnostics;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using Lextm.SharpSnmpLib.Security;
using Microsoft.Extensions.Logging.Abstractions;
using NetSentinel.Core;

namespace NetSentinel.Snmp;

public sealed class SnmpWalkClient
{
    private readonly ILogger<SnmpWalkClient> _logger;

    public SnmpWalkClient(ILogger<SnmpWalkClient>? logger = null)
    {
        _logger = logger ?? NullLogger<SnmpWalkClient>.Instance;
    }

    public Task<WalkResult> WalkAsync(DevicePollTarget target, string baseOid, int maxRows, CancellationToken cancellationToken)
        => Task.Run(() => Walk(target, baseOid, maxRows, cancellationToken), cancellationToken);

    private WalkResult Walk(DevicePollTarget target, string baseOid, int maxRows, CancellationToken cancellationToken)
    {
        var root = SnmpWalkLogic.Normalize(baseOid);
        if (!SnmpWalkLogic.IsOid(root))
        {
            return Fail(root, maxRows, "Enter a numeric OID such as 1.3.6.1.2.1.1.");
        }

        if (maxRows is < 1 or > SnmpWalkLogic.MaxRowsLimit)
        {
            return Fail(root, maxRows, $"Max rows must be between 1 and {SnmpWalkLogic.MaxRowsLimit}.");
        }

        IPEndPoint endpoint;
        try
        {
            endpoint = Resolve(target.Host, target.Port);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Fail(root, maxRows, $"Could not resolve {target.Host}.");
        }

        var session = new Session
        {
            Endpoint = endpoint,
            Target = target,
            TimeoutMs = Math.Clamp(target.TimeoutMs, 200, 30_000),
            Retries = Math.Clamp(target.Retries, 0, 5),
            Clock = Stopwatch.StartNew()
        };

        try
        {
            if (target.Version == SnmpVersion.V3)
            {
                session.Privacy = SnmpPrivacy.Create(target.V3AuthProtocol, target.V3AuthPassword, target.V3PrivProtocol, target.V3PrivPassword);
                session.Report = Discover(session);
            }

            var rows = new List<WalkRow>();
            var previous = root;
            string? limit = null;
            var sawEnd = false;
            var iterations = 0;
            while (rows.Count < maxRows && iterations < maxRows + 2)
            {
                cancellationToken.ThrowIfCancellationRequested();
                iterations++;
                if (Remaining(session) < TimeSpan.FromMilliseconds(200))
                {
                    if (rows.Count == 0)
                    {
                        return Fail(root, maxRows, TimeoutMessage(target));
                    }

                    limit = "time";
                    break;
                }

                PduResult batch;
                try
                {
                    var repetitions = Math.Min(10, Math.Max(1, maxRows - rows.Count + 1));
                    batch = target.Version == SnmpVersion.V1
                        ? GetNext(session, previous)
                        : GetBulk(session, previous, repetitions);
                }
                catch (Exception ex) when (IsGiveUp(ex))
                {
                    if (rows.Count == 0)
                    {
                        return Fail(root, maxRows, FailureMessage(ex, target));
                    }

                    limit = "time";
                    break;
                }

                if (batch.Status == ErrorCode.NoSuchName)
                {
                    if (rows.Count == 0)
                    {
                        return Fail(root, maxRows, SnmpWalkLogic.NoSuchText("noSuchName", root));
                    }

                    sawEnd = true;
                    break;
                }

                if (batch.Status != ErrorCode.NoError)
                {
                    if (rows.Count == 0)
                    {
                        return Fail(root, maxRows, $"SNMP error {batch.Status} talking to {target.Host}:{target.Port}.");
                    }

                    break;
                }

                var stop = false;
                foreach (var variable in batch.Variables)
                {
                    var outcome = Consider(root, previous, rows, maxRows, variable);
                    previous = outcome.Previous;
                    if (outcome.Error is not null)
                    {
                        return Fail(root, maxRows, outcome.Error);
                    }

                    if (outcome.Limit is not null)
                    {
                        limit = outcome.Limit;
                    }

                    if (outcome.SawEnd)
                    {
                        sawEnd = true;
                    }

                    if (outcome.Stop)
                    {
                        stop = true;
                        break;
                    }
                }

                if (stop || batch.Variables.Count == 0)
                {
                    break;
                }
            }

            if (limit is null && !sawEnd && rows.Count >= maxRows)
            {
                limit = "rows";
            }

            AttachLabels(session, rows);
            var truncated = limit is not null;
            _logger.LogDebug(
                "SNMP walk {Host}:{Port} {Oid} rows={Count} truncated={Truncated}",
                target.Host,
                target.Port,
                root,
                rows.Count,
                truncated);
            return Success(root, rows, maxRows, truncated, limit);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogDebug(ex, "SNMP walk failed for {Host}:{Port}", target.Host, target.Port);
            return Fail(root, maxRows, FailureMessage(ex, target));
        }
    }

    private void AttachLabels(Session session, List<WalkRow> rows)
    {
        if (rows.Count == 0)
        {
            return;
        }

        var extras = new Dictionary<string, string>(StringComparer.Ordinal);
        var wanted = SnmpWalkLogic.CompanionOids(rows.Select(row => row.Oid));
        for (var offset = 0; offset < wanted.Count; offset += 12)
        {
            if (Remaining(session) < TimeSpan.FromMilliseconds(200))
            {
                break;
            }

            var chunk = wanted.Skip(offset).Take(12).ToList();
            try
            {
                var reply = Get(session, chunk);
                if (reply.Status != ErrorCode.NoError)
                {
                    continue;
                }

                foreach (var variable in reply.Variables)
                {
                    if (SnmpValues.IsException(variable.Data))
                    {
                        continue;
                    }

                    extras[SnmpWalkLogic.Normalize(variable.Id.ToString())] = Display(variable.Data);
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug(ex, "Sensor name lookup stopped");
                break;
            }
        }

        SnmpWalkLogic.ApplyLabels(rows, extras);
    }

    private readonly record struct Step(string Previous, bool Stop, bool SawEnd, string? Limit, string? Error);

    private static Step Consider(string root, string previous, List<WalkRow> rows, int maxRows, Variable variable)
    {
        var type = TypeName(variable.Data);
        var oid = SnmpWalkLogic.Normalize(variable.Id.ToString());
        var numeric = SnmpValues.AsDouble(variable.Data) is not null;
        var probe = new WalkProbe(oid, type, Display(variable.Data), numeric);
        switch (SnmpWalkLogic.Decide(root, probe, rows.Count, maxRows))
        {
            case WalkStop.Keep:
                if (SnmpWalkLogic.Compare(oid, previous) <= 0)
                {
                    return rows.Count == 0
                        ? new Step(previous, true, false, null, $"The device did not advance past {root}.")
                        : new Step(previous, true, false, null, null);
                }

                rows.Add(new WalkRow
                {
                    Oid = oid,
                    Type = type,
                    Value = probe.Value,
                    Numeric = numeric,
                    Kind = SnmpWalkLogic.GuessKind(type, numeric)
                });
                return new Step(oid, false, false, null, null);
            case WalkStop.RowCap:
                return new Step(previous, true, false, "rows", null);
            case WalkStop.NoSuch:
                if (rows.Count == 0)
                {
                    return new Step(previous, true, true, null, SnmpWalkLogic.NoSuchText(type, string.IsNullOrEmpty(oid) ? root : oid));
                }

                return new Step(previous, true, true, null, null);
            default:
                return new Step(previous, true, true, null, null);
        }
    }

    private PduResult GetNext(Session session, string oid)
    {
        var reply = Exchange(session, () =>
        {
            var variables = new List<Variable> { new(new ObjectIdentifier(oid)) };
            if (session.Target.Version == SnmpVersion.V3)
            {
                return new GetNextRequestMessage(
                    VersionCode.V3,
                    Messenger.NextMessageId,
                    Messenger.NextRequestId,
                    new OctetString(session.Target.V3User ?? ""),
                    new OctetString(session.Target.V3Context ?? ""),
                    variables,
                    session.Privacy!,
                    Messenger.MaxMessageSize,
                    session.Report!);
            }

            var version = session.Target.Version == SnmpVersion.V1 ? VersionCode.V1 : VersionCode.V2;
            return new GetNextRequestMessage(
                Messenger.NextRequestId,
                version,
                new OctetString(session.Target.Community ?? ""),
                variables);
        });
        return new PduResult(reply.Pdu().Variables, reply.Pdu().ErrorStatus.ToErrorCode());
    }

    private PduResult GetBulk(Session session, string oid, int repetitions)
    {
        var reply = SendBulk(session, oid, repetitions);
        var status = reply.Pdu().ErrorStatus.ToErrorCode();
        if (status == ErrorCode.TooBig && repetitions > 1)
        {
            reply = SendBulk(session, oid, 1);
            status = reply.Pdu().ErrorStatus.ToErrorCode();
        }

        return new PduResult(reply.Pdu().Variables, status);
    }

    private ISnmpMessage SendBulk(Session session, string oid, int repetitions)
        => Exchange(session, () =>
        {
            var variables = new List<Variable> { new(new ObjectIdentifier(oid)) };
            if (session.Target.Version == SnmpVersion.V3)
            {
                return new GetBulkRequestMessage(
                    VersionCode.V3,
                    Messenger.NextMessageId,
                    Messenger.NextRequestId,
                    new OctetString(session.Target.V3User ?? ""),
                    new OctetString(session.Target.V3Context ?? ""),
                    0,
                    repetitions,
                    variables,
                    session.Privacy!,
                    Messenger.MaxMessageSize,
                    session.Report!);
            }

            return new GetBulkRequestMessage(
                Messenger.NextRequestId,
                VersionCode.V2,
                new OctetString(session.Target.Community ?? ""),
                0,
                repetitions,
                variables);
        });

    private PduResult Get(Session session, IReadOnlyList<string> oids)
    {
        var reply = Exchange(session, () =>
        {
            var variables = oids.Select(item => new Variable(new ObjectIdentifier(item))).ToList();
            if (session.Target.Version == SnmpVersion.V3)
            {
                return new GetRequestMessage(
                    VersionCode.V3,
                    Messenger.NextMessageId,
                    Messenger.NextRequestId,
                    new OctetString(session.Target.V3User ?? ""),
                    new OctetString(session.Target.V3Context ?? ""),
                    variables,
                    session.Privacy!,
                    Messenger.MaxMessageSize,
                    session.Report!);
            }

            var version = session.Target.Version == SnmpVersion.V1 ? VersionCode.V1 : VersionCode.V2;
            return new GetRequestMessage(
                Messenger.NextRequestId,
                version,
                new OctetString(session.Target.Community ?? ""),
                variables);
        });
        return new PduResult(reply.Pdu().Variables, reply.Pdu().ErrorStatus.ToErrorCode());
    }

    private ISnmpMessage Exchange(Session session, Func<ISnmpMessage> create)
    {
        var attempts = session.Retries + 1;
        Exception? last = null;
        for (var attempt = 0; attempt < attempts; attempt++)
        {
            var budget = Remaining(session);
            if (budget < TimeSpan.FromMilliseconds(200))
            {
                throw new System.TimeoutException(SnmpWalkLogic.TimeoutText());
            }

            var timeout = (int)Math.Min(session.TimeoutMs, budget.TotalMilliseconds);
            try
            {
                var reply = create().GetResponse(timeout, session.Endpoint);
                if (reply is ReportMessage && session.Target.Version == SnmpVersion.V3 && attempt == 0)
                {
                    session.Report = reply;
                    last = new InvalidOperationException(ReportText(reply));
                    continue;
                }

                if (reply is ReportMessage)
                {
                    throw new InvalidOperationException(ReportText(reply));
                }

                return reply;
            }
            catch (Exception ex) when (IsRetriable(ex) && attempt < attempts - 1)
            {
                last = ex;
            }
        }

        throw last ?? new System.TimeoutException(SnmpWalkLogic.TimeoutText());
    }

    private static ISnmpMessage Discover(Session session)
    {
        var budget = Remaining(session);
        if (budget < TimeSpan.FromMilliseconds(200))
        {
            throw new System.TimeoutException(SnmpWalkLogic.TimeoutText());
        }

        var timeout = (int)Math.Min(session.TimeoutMs, budget.TotalMilliseconds);
        var discovery = Messenger.GetNextDiscovery(SnmpType.GetRequestPdu);
        return discovery.GetResponse(timeout, session.Endpoint);
    }

    private static TimeSpan Remaining(Session session)
        => SnmpWalkLogic.TimeLimit - session.Clock.Elapsed;

    private static string ReportText(ISnmpMessage reply)
    {
        var ids = string.Join(", ", reply.Variables().Select(variable => variable.Id.ToString()));
        return string.IsNullOrEmpty(ids) ? "The device sent an SNMPv3 report." : $"The device sent an SNMPv3 report ({ids}).";
    }

    private static string TimeoutMessage(DevicePollTarget target)
        => $"SNMP timed out talking to {target.Host}:{target.Port}. Check the host, UDP port, and credentials.";

    private static string FailureMessage(Exception ex, DevicePollTarget target)
    {
        if (IsTimeout(ex))
        {
            return TimeoutMessage(target);
        }

        var detail = ex.Message.Trim();
        if (detail.Length > 180)
        {
            detail = detail[..180];
        }

        if (string.IsNullOrEmpty(detail))
        {
            return TimeoutMessage(target);
        }

        return $"SNMP request to {target.Host}:{target.Port} failed: {detail}";
    }

    private static bool IsGiveUp(Exception ex) => IsRetriable(ex) || ex is InvalidOperationException;

    private static bool IsRetriable(Exception ex)
    {
        for (var current = ex; current is not null; current = current.InnerException)
        {
            if (current is System.TimeoutException or SocketException or IOException)
            {
                return true;
            }

            if (current.GetType().Name.Contains("Timeout", StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsTimeout(Exception ex)
    {
        for (var current = ex; current is not null; current = current.InnerException)
        {
            if (current is System.TimeoutException || current.GetType().Name.Contains("Timeout", StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static string TypeName(ISnmpData data) => data.TypeCode switch
    {
        SnmpType.Integer32 => "Integer32",
        SnmpType.Counter32 => "Counter32",
        SnmpType.Counter64 => "Counter64",
        SnmpType.Gauge32 => "Gauge32",
        SnmpType.TimeTicks => "TimeTicks",
        SnmpType.OctetString => "OctetString",
        SnmpType.ObjectIdentifier => "ObjectIdentifier",
        SnmpType.IPAddress => "IpAddress",
        SnmpType.Null => "Null",
        SnmpType.NoSuchObject => "NoSuchObject",
        SnmpType.NoSuchInstance => "NoSuchInstance",
        SnmpType.EndOfMibView => "EndOfMibView",
        SnmpType.Opaque => "Opaque",
        _ => data.TypeCode.ToString()
    };

    private static string Display(ISnmpData data)
    {
        var text = SnmpValues.Format(data);
        var cleaned = new string(text.Select(ch => char.IsControl(ch) ? ' ' : ch).ToArray()).Trim();
        return cleaned.Length <= 500 ? cleaned : cleaned[..500];
    }

    private static IPEndPoint Resolve(string host, int port)
    {
        if (IPAddress.TryParse(host, out var address))
        {
            return new IPEndPoint(address, port);
        }

        var addresses = Dns.GetHostAddresses(host);
        var ipv4 = addresses.FirstOrDefault(item => item.AddressFamily == AddressFamily.InterNetwork) ?? addresses.FirstOrDefault();
        if (ipv4 is null)
        {
            throw new InvalidOperationException($"Could not resolve {host}.");
        }

        return new IPEndPoint(ipv4, port);
    }

    private static WalkResult Success(string root, List<WalkRow> rows, int maxRows, bool truncated, string? limit)
    {
        string? message = null;
        if (truncated && limit == "rows")
        {
            message = SnmpWalkLogic.RowCapText(rows.Count, maxRows);
        }
        else if (truncated && limit == "time")
        {
            message = SnmpWalkLogic.TimeText(rows.Count);
        }
        else if (rows.Count == 0)
        {
            message = SnmpWalkLogic.EmptyText(root);
        }

        return new WalkResult
        {
            Ok = true,
            BaseOid = root,
            Truncated = truncated,
            Limit = limit,
            Message = message,
            MaxRows = maxRows,
            Rows = rows
        };
    }

    private static WalkResult Fail(string root, int maxRows, string error) => new()
    {
        Ok = false,
        Error = error,
        BaseOid = root,
        MaxRows = maxRows
    };

    private readonly record struct PduResult(IList<Variable> Variables, ErrorCode Status);

    private sealed class Session
    {
        public required IPEndPoint Endpoint { get; init; }
        public required DevicePollTarget Target { get; init; }
        public required int TimeoutMs { get; init; }
        public required int Retries { get; init; }
        public required Stopwatch Clock { get; init; }
        public ISnmpMessage? Report { get; set; }
        public IPrivacyProvider? Privacy { get; set; }
    }
}
