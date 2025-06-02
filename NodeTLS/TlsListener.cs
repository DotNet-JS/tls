using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace NodeTLS;

public class TlsListener
{

    public static async Task<TlsListener> Create(
        string host,
        int port,
        Func<string, Task<string>> sniCallback,
        Func<TlsClient, Task> read)
    {
        var listener = new TlsListener(host, port, sniCallback, read);
        await listener.CreateInternal();
        return listener;
    }

    CancellationTokenSource cts = new CancellationTokenSource();
    private string host;
    private int port;
    private Func<string, Task<string>> sniCallback;
    private Func<TlsClient, Task> read;

    public TlsListener(string host, int port, Func<string, Task<string>> sniCallback, Func<TlsClient, Task> read)
    {
        this.host = host;
        this.port = port;
        this.sniCallback = sniCallback;
        this.read = read;
    }
    
    private async Task CreateInternal()
    {
        var server = new TcpListener(string.IsNullOrWhiteSpace(host)
            ? System.Net.IPAddress.None
            : System.Net.IPAddress.Parse(host), port);
        await Task.Run(async () => {
            while (!cts.IsCancellationRequested)
            {
                try
                {
                    await AcceptSocket(server);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine(ex);
                }
            }
        });
    }

    private async Task AcceptSocket(TcpListener server)
    {
        var client = await server.AcceptTcpClientAsync();
        try
        {
            using var ssl = new SslStream(client.GetStream());

            await ssl.AuthenticateAsServerAsync(AuthenticateAsync, this, CancellationToken.None);

            using var tlsClient = new TlsClient(ssl.TargetHostName, client, ssl);

            await this.read(tlsClient);

        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine(ex);
            try
            {
                client.Close();
            } catch { }
        }
    }

    private static async ValueTask<SslServerAuthenticationOptions> AuthenticateAsync(SslStream stream, SslClientHelloInfo clientHelloInfo, object? state, CancellationToken cancellationToken)
    {
        var listener = (state as TlsListener)!;
        var name = clientHelloInfo.ServerName;

        var jsonNode = JsonNode.Parse(await listener.sniCallback(name))!;
        var cert = jsonNode.AsObject()["cert"]!.AsValue().ToString();
        var key = jsonNode.AsObject()["key"]!.AsValue().ToString();

        var xCert = X509Certificate2.CreateFromPem(cert, key);

        return new SslServerAuthenticationOptions
        {
            ServerCertificateContext = SslStreamCertificateContext.Create(xCert, null)

        };
    }
}
