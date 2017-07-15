alias rustc='docker run --rm -it -v $(pwd):/app -v ~/.cargo/registry:/home/app/.cargo/registry rustdev rustc '

alias cargo='docker run --rm -it -v $(pwd):/app -v ~/.cargo/registry:/home/app/.cargo/registry rustdev cargo '

alias rustdev='docker run --rm -it -v $(pwd):/app -v ~/.cargo/registry:/home/app/.cargo/registry rustdev '
