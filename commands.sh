alias rustc='docker run --rm -it -v $(pwd):/app -v ~/.cargo/registry:/home/app/.cargo/registry rust_static rustc '

alias cargo='docker run --rm -it -v $(pwd):/app -v ~/.cargo/registry:/home/app/.cargo/registry rust_static cargo '

