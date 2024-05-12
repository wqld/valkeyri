run:
    cargo xtask build-ebpf
    RUST_LOG=info cargo xtask run -- --iface lo

run-release:
    cargo xtask build-ebpf --release
    cargo build --release
    sudo ./target/release/valkeyri --iface lo

run-nginx:
    docker run -p 8080:80 --rm nginx

run-redis:
    docker run --name some-redis -d -p 6379:6379 redis
    docker run -it --link some-redis:redis --rm redis redis-cli -h redis -p 6379

try-rsb:
    docker run --network host --rm ghcr.io/gamelife1314/rsb -d 5 -l http://host.docker.internal:3000

build-and-load-image:
    cargo xtask build-ebpf
    cargo build --target $(uname -m)-unknown-linux-musl
    docker build --build-arg ARCH=$(uname -m) -t valkeyri:test .
    kind load docker-image valkeyri:test

run-debug-container:
    kubectl debug redis-master-0 --image=valkeyri:test --profile='sysadmin' -it

dump-tcp:
    sudo tcpdump -i lo port 6379
