# Docker RE and Navigation

To share a directory in the container:

```bash
docker run -it -v /home/share:/share trailofbits/eth-security-toolbox
```

Running an image:

```bash
docker run --rm -it image-name
```



### Analyzing an Image

We could try manually untarring the provided file and combing through the contents, but Docker does a much better job of this. [`docker load`](https://docs.docker.com/engine/reference/commandline/load/) allows us to import an image from a file, so let's do that.

```bash
docker load --input image.tar
```

Inspect metadata:

```bash
docker inspect image-name
```

Instead of using the image's default start-up command, we can specify a different command. To explore the filesystem of the container we can drop into a shell using the command `bash`:

```bash
docker run --rm -it image-name bash
```

Installing extra packages from within container

```bash
apk add strace
```



### Analyzing Files within Containers

Copying from the container's filesystem and extracting file:

```bash
docker run --detach --rm -it image-name bash
b617744dd629e8208738b255bb76ebdb2770382fd7d453788c59076e783254f8

docker cp b617744dd629e8208738b255bb76ebdb2770382fd7d453788c59076e783254f8:/usr/bin/make ./make
```

**<u>Extending container:</u>**

Extending the container with a `Dockerfile`:

```bash
FROM image-name

# install git, gdb, and curl
RUN apk add git gdb curl
# install gef
RUN bash -c "$(curl -fsSL http://gef.blah.cat/sh)"

CMD ["gdb", "make"]
```

Then we can build it with:

```bash
docker build -t image-reversing .
```

And finally run it with:

```bash
docker --rm -it image-reversing

#should drop into a gdb-gef
```

