/** A relay proxy that can drop, duplicate, reorder, delay, relabel or flip frames. */

import http from "node:http";

import { WebSocket, WebSocketServer } from "ws";

export class HostileProxy {
  /**
   * A WebSocket and HTTP relay in front of the real one, with armed faults.
   * Each armed fault damages one data frame in its direction, on whichever of
   * the two client sockets sends the next one. Everything else is forwarded.
   */
  constructor(address, target, httpTarget) {
    this.address = address;
    this.target = target;
    this.httpTarget = httpTarget;
    this.port = null;
    this._faults = { up: [], down: [] };
    this._held = { up: null, down: null };
    this._server = null;
    this._websocketServer = null;
    this._connections = new Set();
  }

  get url() {
    return `ws://${this.address}:${this.port}`;
  }

  async start() {
    this._server = http.createServer((request, response) => this._forward(request, response));
    this._websocketServer = new WebSocketServer({ noServer: true });
    this._server.on("upgrade", (request, socket, head) => {
      this._websocketServer.handleUpgrade(request, socket, head, (client) => {
        this._connect(client, request);
      });
    });
    await new Promise((resolve, reject) => {
      this._server.once("error", reject);
      this._server.listen(0, this.address, resolve);
    });
    this.port = this._server.address().port;
  }

  async stop() {
    for (const connection of this._connections) connection.close();
    await new Promise((resolve) => this._websocketServer.close(resolve));
    await new Promise((resolve) => this._server.close(resolve));
  }

  arm(direction, action, delay = 300) {
    this._faults[direction].push({ action, delay });
  }

  _forward(request, response) {
    const upstream = http.request(
      this.httpTarget + request.url,
      { method: request.method, headers: { authorization: request.headers.authorization ?? "" } },
      (answer) => {
        response.writeHead(answer.statusCode, answer.headers);
        answer.pipe(response);
      },
    );
    upstream.on("error", () => {
      response.writeHead(503, {});
      response.end();
    });
    upstream.end();
  }

  _connect(client, request) {
    // The client may send `auth` before the upstream socket is open; keep its
    // frames queued rather than dropping events nobody listens to yet.
    client.pause();
    const upstream = new WebSocket(this.target + request.url);
    this._connections.add(client);
    upstream.on("open", () => {
      this._connections.add(upstream);
      client.on("message", (data, isBinary) => this._pipe(client, upstream, "up", data, isBinary));
      upstream.on("message", (data, isBinary) => this._pipe(upstream, client, "down", data, isBinary));
      client.resume();
    });
    client.on("close", () => upstream.close());
    upstream.on("close", () => client.close());
    upstream.on("error", () => client.close());
    client.on("error", () => upstream.close());
  }

  _pipe(source, destination, direction, data, isBinary) {
    if (!isBinary || data.length === 0 || data[0] !== 0x01) {
      destination.send(data, { binary: isBinary });
      return;
    }
    const held = this._held[direction];
    if (held !== null) {
      this._held[direction] = null;
      destination.send(data, { binary: true });
      destination.send(held, { binary: true });
      return;
    }
    const fault = this._faults[direction].shift();
    if (fault === undefined) {
      destination.send(data, { binary: true });
      return;
    }
    switch (fault.action) {
      case "drop":
        return;
      case "duplicate":
        destination.send(data, { binary: true });
        destination.send(data, { binary: true });
        return;
      case "reorder":
        this._held[direction] = data;
        return;
      case "delay":
        setTimeout(() => destination.send(data, { binary: true }), fault.delay);
        return;
      case "relabel":
        destination.send(Buffer.from([0x01, 0x05]), { binary: true });
        return;
      case "flip": {
        const copy = Buffer.from(data);
        copy[3] ^= 0x01;
        destination.send(copy, { binary: true });
        return;
      }
      default:
        destination.send(data, { binary: true });
    }
  }
}
