using System.Net;
using System.Net.Security;
using System.Net.Sockets;

namespace NodeTLS;

public class TlsClient: System.IDisposable
{
    private readonly string targetHostName;
    private readonly TcpClient client;
    private SslStream ssl;
    private bool disposedValue;

    public string ServerName => targetHostName;

    public TlsClient(string targetHostName, TcpClient client, SslStream ssl)
    {
        this.targetHostName = targetHostName;
        this.client = client;
        this.ssl = ssl;
    }

    public Task ForwardToSocket(string host, int port, bool includeRemoteEndPoint = true)
    {
        return Task.Run(async () => {
            try
            {
                using var client = new Socket(AddressFamily.Ipx, SocketType.Stream, ProtocolType.Tcp);
                var endPoint = new IPEndPoint(IPAddress.Parse(host), port);
                await client.ConnectAsync(endPoint);
                using var ns = new NetworkStream(client, true);

                await Task.WhenAll(this.ssl.CopyToAsync(ns), ns.CopyToAsync(ssl));
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(ex.ToString());
            }
        });
    }


    public Task ForwardToUnixSocket(string host, string port, bool includeRemoteEndPoint = true)
    {
        return Task.Run(async () => {
            try
            {
                using var client = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.IP);
                var endPoint = new UnixDomainSocketEndPoint(port);

                await client.ConnectAsync(endPoint);
                using var ns = new NetworkStream(client, true);

                await Task.WhenAll(this.ssl.CopyToAsync(ns), ns.CopyToAsync(ssl));

            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(ex.ToString());
            }
        });
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!disposedValue)
        {
            if (disposing)
            {
                try {
                    ssl.Close();
                } catch {
                }
                try {
                    client.Close();
                } catch { }
            }

            // TODO: free unmanaged resources (unmanaged objects) and override finalizer
            // TODO: set large fields to null
            disposedValue = true;
        }
    }

    // // TODO: override finalizer only if 'Dispose(bool disposing)' has code to free unmanaged resources
    // ~TlsClient()
    // {
    //     // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
    //     Dispose(disposing: false);
    // }

    public void Dispose()
    {
        // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }
}
