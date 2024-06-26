# valkeyri
Provide an in-kernel cache for valkey or redis

## Constraints

- It only runs on Linux that supports the XDP feature.
- The Redis client must use a connection pool. I wrote the logic under the condition that the connection is maintained, as there is overhead for all processing of the TCP state.
- Currently, it sends a 41 response for all get requests. This will be modified as the cache strategy is implemented.

## Performance

### Environment

Redis was run using Docker as follows: `docker run --name redis -d -p 6379:6379 redis`

The Redis client used in the test is [redis-rs](https://github.com/redis-rs/redis-rs), and the connection pool was implemented using [r2d2](https://github.com/sfackler/r2d2). When the client runs, it establishes 300 connections with Redis.

### Benchmark

- Benchmark tool: [rsb: a http server benchmark tool written in rust](https://github.com/gamelife1314/rsb)
- Command: `docker run --network host --rm ghcr.io/gamelife1314/rsb -d 5 -l http://host.docker.internal:3000`

#### without valkeyri

```sh
Statistics         Avg          Stdev          Max
  Reqs/sec        654.40        25.54         694.00
  Latency        75.63ms       27.97ms       197.37ms
  Latency Distribution
     50%     53.13ms
     75%     63.62ms
     90%     70.10ms
     99%     74.81ms
  HTTP codes:
    1XX - 0, 2XX - 3321, 3XX - 0, 4XX - 0, 5XX - 0
    others - 0
  Throughput:     661.08/s
```

#### with valkeyri (SKB mode)

`just run-release`

```sh
Statistics         Avg          Stdev          Max
  Reqs/sec       9079.80        227.76       9318.00
  Latency         5.50ms        1.78ms       23.15ms
  Latency Distribution
     50%      4.21ms
     75%      4.71ms
     90%      5.08ms
     99%      5.42ms
  HTTP codes:
    1XX - 0, 2XX - 45408, 3XX - 0, 4XX - 0, 5XX - 0
    others - 0
  Throughput:    9093.90/s
```

Even without XDP native mode, you can confirm that there is more than a 10x performance improvement.
