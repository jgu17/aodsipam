FROM golang:1.19
ADD . /usr/src/aodsipam
RUN mkdir -p $GOPATH/src/aodsipam
WORKDIR $GOPATH/src/aodsipam
COPY . .
RUN ./hack/build-go.sh

FROM alpine:latest
COPY --from=0 /go/src/aodsipam/bin/aodsipam .
COPY script/install-cni.sh .
CMD ["/install-cni.sh"]
