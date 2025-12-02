package main

import (
	"context"
	cr "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/wavesplatform/gowaves/pkg/client"
	"github.com/wavesplatform/gowaves/pkg/crypto"
	"github.com/wavesplatform/gowaves/pkg/proto"
	"golang.org/x/crypto/ssh"
)

func callMine(miner string) error {
	var networkByte = byte(55)
	var nodeURL = AnoteNodeURL

	// Create new HTTP client to send the transaction to public TestNet nodes
	cl, err := client.NewClient(client.Options{BaseUrl: nodeURL, Client: &http.Client{}})
	if err != nil {
		log.Println(err)
		return err
	}

	// Context to cancel the request execution on timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create sender's public key from BASE58 string
	sender, err := crypto.NewPublicKeyFromBase58(conf.PublicKey)
	if err != nil {
		log.Println(err.Error())
		return err
	}

	rec, err := proto.NewRecipientFromString(DappAddress)
	if err != nil {
		log.Println(err)
		return err
	}

	args := proto.Arguments{}
	minerArg := proto.NewStringArgument(miner)
	args.Append(minerArg)

	call := proto.FunctionCall{
		Name:      "mineExecute",
		Arguments: args,
	}

	// payments := proto.ScriptPayments{}
	// payments.Append(proto.ScriptPayment{
	// 	Amount: abi.Balance - RewardFee,
	// })

	fa := proto.OptionalAsset{}

	// Current time in milliseconds
	ts := uint64(time.Now().Unix() * 1000)

	tr := proto.NewUnsignedInvokeScriptWithProofs(
		2,
		networkByte,
		sender,
		rec,
		call,
		nil,
		fa,
		RewardFee,
		ts)

	tr.Proofs = proto.NewProofs()

	sk, err := crypto.NewSecretKeyFromBase58(conf.PrivateKey)
	if err != nil {
		log.Println(err)
		return err
	}

	tr.Sign(55, sk)

	// // Send the transaction to the network
	resp, err := cl.Transactions.Broadcast(ctx, tr)
	if err != nil {
		log.Println(err)
		return err
	}
	defer resp.Body.Close()

	return nil
}

func callWinner() error {
	var networkByte = byte(55)
	var nodeURL = AnoteNodeURL

	// Create new HTTP client to send the transaction to public TestNet nodes
	cl, err := client.NewClient(client.Options{BaseUrl: nodeURL, Client: &http.Client{}})
	if err != nil {
		log.Println(err)
		return err
	}

	// Context to cancel the request execution on timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create sender's public key from BASE58 string
	sender, err := crypto.NewPublicKeyFromBase58(conf.PublicKey)
	if err != nil {
		log.Println(err.Error())
		return err
	}

	rec, err := proto.NewRecipientFromString(DappAddress)
	if err != nil {
		log.Println(err)
		return err
	}

	args := proto.Arguments{}

	privKey, _ := getPrivateKey()

	// pubk, _ := x509.MarshalPKIXPublicKey(&privKey.PublicKey)

	publicKeyBytes, err := os.ReadFile("./public.pem")
	if err != nil {
		log.Fatal(fmt.Errorf("failed to load public key: %s", err))
	}

	publicBlock, _ := pem.Decode(publicKeyBytes)
	if publicBlock == nil || publicBlock.Type != "PUBLIC KEY" {
		log.Fatal(fmt.Errorf("failed to decode PEM block containing public key"))
	}

	// Parse the public key
	publicKey, err := x509.ParsePKIXPublicKey(publicBlock.Bytes)
	if err != nil {
		log.Fatal(fmt.Errorf("parse cert: %s", err))
	}

	// pubk, _ := x509.MarshalPKIXPublicKey(publicKey)

	// log.Println(base64.RawStdEncoding.EncodeToString(pubk))

	blockId := getBlockId()

	gid, err := sign(blockId, privKey)
	if err != nil {
		log.Println(err)
	}
	// log.Println(gid)

	// log.Println(base64.StdEncoding.EncodeToString(gid))

	gameId := proto.NewStringArgument(blockId)
	// rsaSign := proto.NewStringArgument("[9 232 18 234 10 173 198 156 247 101 46 223 63 84 141 59 33 193 61 56 27 44 90 21 150 33 21 52 12 47 25 192 37 184 184 189 39 108 157 206 251 89 89 245 133 98 247 219 209 200 146 83 205 215 123 184 171 13 186 134 244 30 163 167 140 194 109 96 219 245 72 41 190 130 195 24 152 9 156 192 155 253 224 229 246 36 59 3 76 201 121 211 245 195 127 213 75 189 143 132 163 248 254 188 188 101 16 85 209 34 70 156 127 2 221 188 212 244 45 10 184 8 252 250 103 108 39 114 29 55 28 25 18 170 48 157 216 206 108 55 178 133 59 233 75 208 61 103 220 150 49 227 42 195 41 63 81 210 155 66 184 253 251 183 144 63 50 56 104 67 253 132 103 17 186 35 127 250 230 170 188 215 92 119 130 13 210 213 155 173 35 131 44 85 218 15 113 160 121 112 123 29 103 122 198 104 103 201 87 60 152 185 229 43 108 113 66 203 55 22 206 77 219 63 65 100 112 47 251 52 54 151 128 202 229 3 53 231 221 84 175 57 134 155 126 214 79 101 107 21 194 205 219 222 221 81]")
	// rsaSign := proto.BinaryArgument{
	// 	Value: gid,
	// }
	rsaSign := proto.NewStringArgument(base64.StdEncoding.EncodeToString(gid))
	// rsaSign := proto.NewStringArgument("hMJTUbrr3QsNtJaMySQWg7bs8lxXikhrvDxSFYVwJmLH91wnIlPx8H1dRw4V6xym8q+xH8OFIS3ibG2sb/W6aUO/Lnrn88/bpEagPyOSp5TfZ459oBKLHmozCgNW7R97j4zczgev9knqsQawLDD6aI7QG3o4caCyNjMazqSqJWNXveFSkZDtdzCPGxfCwDQPZago59xKrXgeidVUTePrn0I5V3O+/X7VNtIB27I9brN8ixO54Zcduz8Ly7F40haQYDz7wgZMU+xyr6Gh9OFZggaVvatO6AFp5M4UnWhgPq78KiEO5PCXPjNRLJXreLK7h+eK3tKTAx7WMOfm55mIVQ==")

	args.Append(gameId)
	args.Append(rsaSign)

	msg := []byte(blockId)

	// Before signing, we need to hash our message
	// The hash is what we actually sign
	msgHash := sha256.New()
	_, err = msgHash.Write(msg)
	if err != nil {
		panic(err)
	}
	msgHashSum := msgHash.Sum(nil)

	err = rsa.VerifyPSS(publicKey.(*rsa.PublicKey), cr.SHA256, msgHashSum, gid, nil)
	if err != nil {
		log.Println("could not verify signature: ", err)
	}
	// If we don't get any error from the `VerifyPSS` method, that means our
	// signature is valid
	log.Println("signature verified")

	// log.Println(args)

	call := proto.FunctionCall{
		Name:      "mineWinner",
		Arguments: args,
	}

	// payments := proto.ScriptPayments{}
	// payments.Append(proto.ScriptPayment{
	// 	Amount: abi.Balance - RewardFee,
	// })

	fa := proto.OptionalAsset{}

	// Current time in milliseconds
	ts := uint64(time.Now().Unix() * 1000)

	tr := proto.NewUnsignedInvokeScriptWithProofs(
		2,
		networkByte,
		sender,
		rec,
		call,
		nil,
		fa,
		RewardFee,
		ts)

	tr.Proofs = proto.NewProofs()

	sk, err := crypto.NewSecretKeyFromBase58(conf.PrivateKey)
	if err != nil {
		log.Println(err)
		return err
	}

	tr.Sign(55, sk)

	// // Send the transaction to the network
	resp, err := cl.Transactions.Broadcast(ctx, tr)
	if err != nil {
		log.Println(err)
		return err
	}
	defer resp.Body.Close()

	return nil
}

func getPublicKey(address string) string {
	pk := ""

	// Create new HTTP client to send the transaction to public TestNet nodes
	client, err := client.NewClient(client.Options{BaseUrl: AnoteNodeURL, Client: &http.Client{}})
	if err != nil {
		log.Println(err)
	}

	// Context to cancel the request execution on timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	a, err := proto.NewAddressFromString(address)
	if err != nil {
		log.Println(err)
	}

	transactions, resp, err := client.Transactions.Address(ctx, a, 100)
	if err != nil {
		log.Println(err)
	}
	defer resp.Body.Close()

	for _, tr := range transactions {
		at := AnoteTransaction{}
		trb, err := json.Marshal(tr)
		json.Unmarshal(trb, &at)
		pk, err := crypto.NewPublicKeyFromBase58(at.SenderPublicKey)
		if err != nil {
			log.Println(err)
		}
		addr, err := proto.NewAddressFromPublicKey(55, pk)
		if err != nil {
			log.Println(err)
		}
		if addr.String() == address {
			return at.SenderPublicKey
		}
	}

	transactions = nil

	return pk
}

type AnoteTransaction struct {
	SenderPublicKey string `json:"senderPublicKey"`
}

func getHeight() uint64 {
	height := uint64(0)

	cl, err := client.NewClient(client.Options{BaseUrl: AnoteNodeURL, Client: &http.Client{}})
	if err != nil {
		log.Println(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	bh, _, err := cl.Blocks.Height(ctx)
	if err != nil {
		log.Println(err)
	} else {
		height = bh.Height
	}

	return height
}

func getPrivateKey() (*rsa.PrivateKey, error) {
	privateKeyBytes, err := os.ReadFile("./private.pem")
	if err != nil {
		log.Fatal(fmt.Errorf("failed to load private key: %s", err))
	}

	// Decode the key into a "block"
	privateBlock, _ := pem.Decode(privateKeyBytes)
	if privateBlock == nil || privateBlock.Type != "PRIVATE KEY" {
		log.Fatal(fmt.Errorf("failed to decode PEM block containing private key"))
	}

	// Parse the private key from the block
	privateKey, err := x509.ParsePKCS8PrivateKey(privateBlock.Bytes)
	if err != nil {
		log.Fatal(fmt.Errorf("failed to parse private key type: %s", err))
	}

	// Check the type of the key
	if _, ok := privateKey.(*rsa.PrivateKey); !ok {
		log.Fatal(fmt.Errorf("invalid key type: %s", reflect.TypeOf(privateKey)))
	}
	return privateKey.(*rsa.PrivateKey), nil
}

func marshalRSAPrivate(priv *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}))
}

func generateKey() (string, string, error) {
	reader := rand.Reader
	bitSize := 2048

	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		return "", "", err
	}

	pub, err := ssh.NewPublicKey(key.Public())
	if err != nil {
		return "", "", err
	}
	pubKeyStr := string(ssh.MarshalAuthorizedKey(pub))
	privKeyStr := marshalRSAPrivate(key)

	return pubKeyStr, privKeyStr, nil
}

func sign(msg string, key *rsa.PrivateKey) ([]byte, error) {
	msgHash := sha256.New()
	_, err := msgHash.Write([]byte(msg))
	if err != nil {
		panic(err)
	}
	msgHashSum := msgHash.Sum(nil)

	// In order to generate the signature, we provide a random number generator,
	// our private key, the hashing algorithm that we used, and the hash sum
	// of our message
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, cr.SHA256, msgHashSum)
	if err != nil {
		panic(err)
	}

	return signature, nil
}

func callMineIntent(miner string) error {
	var networkByte = byte(55)
	var nodeURL = AnoteNodeURL

	// Create new HTTP client to send the transaction to public TestNet nodes
	cl, err := client.NewClient(client.Options{BaseUrl: nodeURL, Client: &http.Client{}})
	if err != nil {
		log.Println(err)
		return err
	}

	// Context to cancel the request execution on timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create sender's public key from BASE58 string
	sender, err := crypto.NewPublicKeyFromBase58(conf.PublicKey)
	if err != nil {
		log.Println(err.Error())
		return err
	}

	rec, err := proto.NewRecipientFromString(DappAddress)
	if err != nil {
		log.Println(err)
		return err
	}

	args := proto.Arguments{}
	addr := proto.NewStringArgument(miner)
	args.Append(addr)

	call := proto.FunctionCall{
		Name:      "mineIntent",
		Arguments: args,
	}

	payments := proto.ScriptPayments{}
	payments.Append(proto.ScriptPayment{
		Amount: 100,
	})

	fa := proto.OptionalAsset{}

	// Current time in milliseconds
	ts := uint64(time.Now().Unix() * 1000)

	tr := proto.NewUnsignedInvokeScriptWithProofs(
		2,
		networkByte,
		sender,
		rec,
		call,
		payments,
		fa,
		RewardFee,
		ts)

	tr.Proofs = proto.NewProofs()

	sk, err := crypto.NewSecretKeyFromBase58(conf.PrivateKey)
	if err != nil {
		log.Println(err)
		return err
	}

	tr.Sign(55, sk)

	// // Send the transaction to the network
	resp, err := cl.Transactions.Broadcast(ctx, tr)
	if err != nil {
		log.Println(err)
		return err
	}
	defer resp.Body.Close()

	return nil
}

func callDelete(miner string) error {
	var networkByte = byte(55)
	var nodeURL = AnoteNodeURL

	// Create new HTTP client to send the transaction to public TestNet nodes
	cl, err := client.NewClient(client.Options{BaseUrl: nodeURL, Client: &http.Client{}})
	if err != nil {
		log.Println(err)
		return err
	}

	// Context to cancel the request execution on timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create sender's public key from BASE58 string
	sender, err := crypto.NewPublicKeyFromBase58(conf.PublicKey)
	if err != nil {
		log.Println(err.Error())
		return err
	}

	rec, err := proto.NewRecipientFromString(DappAddress)
	if err != nil {
		log.Println(err)
		return err
	}

	args := proto.Arguments{}
	minerArg := proto.NewStringArgument(miner)
	args.Append(minerArg)

	call := proto.FunctionCall{
		Name:      "mineDelete",
		Arguments: args,
	}

	fa := proto.OptionalAsset{}

	// Current time in milliseconds
	ts := uint64(time.Now().Unix() * 1000)

	tr := proto.NewUnsignedInvokeScriptWithProofs(
		2,
		networkByte,
		sender,
		rec,
		call,
		nil,
		fa,
		RewardFee,
		ts)

	tr.Proofs = proto.NewProofs()

	sk, err := crypto.NewSecretKeyFromBase58(conf.PrivateKey)
	if err != nil {
		log.Println(err)
		return err
	}

	tr.Sign(55, sk)

	// // Send the transaction to the network
	resp, err := cl.Transactions.Broadcast(ctx, tr)
	if err != nil {
		log.Println(err)
		return err
	}
	defer resp.Body.Close()

	return nil
}

func getData(key string, address *string) (interface{}, error) {
	var a proto.WavesAddress

	wc, err := client.NewClient(client.Options{BaseUrl: AnoteNodeURL, Client: &http.Client{}})
	if err != nil {
		log.Println(err)
	}

	if address == nil {
		pk, err := crypto.NewPublicKeyFromBase58(conf.PublicKey)
		if err != nil {
			return nil, err
		}

		a, err = proto.NewAddressFromPublicKey(55, pk)
		if err != nil {
			return nil, err
		}
	} else {
		a, err = proto.NewAddressFromString(*address)
		if err != nil {
			return nil, err
		}
	}

	ad, _, err := wc.Addresses.AddressesDataKey(context.Background(), a, key)
	if err != nil {
		return nil, err
	}

	if ad.GetValueType().String() == "string" {
		return ad.ToProtobuf().GetStringValue(), nil
	}

	if ad.GetValueType().String() == "boolean" {
		return ad.ToProtobuf().GetBoolValue(), nil
	}

	if ad.GetValueType().String() == "integer" {
		return ad.ToProtobuf().GetIntValue(), nil
	}

	return "", nil
}

func parseItem(value string, index int) interface{} {
	values := strings.Split(value, Sep)
	var val interface{}
	types := strings.Split(values[0], "%")

	if index < len(values)-1 {
		val = values[index+1]
	}

	if val != nil && types[index+1] == "d" {
		intval, err := strconv.Atoi(val.(string))
		if err != nil {
			log.Println(err.Error())
		}
		val = intval
	}

	return val
}

func getBlockId() string {
	addr := AtcAddr

	d, err := getData("blockId", &addr)
	if err != nil || d == nil {
		log.Println(err)
		return ""
	}

	return d.(string)
}
