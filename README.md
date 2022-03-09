# dashmsg

Sign and Verify messages with Dash Private Keys

```bash
git clone https://github.com/dashhive/dashmsg
pushd ./dashmsg/
```

```bash
go build -mod=vendor -o dashmsg ./cmd/dashmsg/
```

```bash
my_privkey='XK5DHnAiSj6HQNsNcDkawd9qdp8UFMdYftdVZFuRreTMJtbJhk8i'

my_msg='dte2022-afrancis|ctafti'

./dashmsg sign "${my_privkey}" "${my_msg}"
```

```txt
IIm+2++GxT4OtTTY4aZK0iKIWh21yxiwomfY76l197qtVB42KVpy53QxS65zq1R9eN2XLcGh2YsedsVtsmrw2OE=
```
