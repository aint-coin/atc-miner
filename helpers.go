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
	// publicKey, err := x509.ParsePKIXPublicKey(publicBlock.Bytes)
	// if err != nil {
	// 	log.Fatal(fmt.Errorf("parse cert: %s", err))
	// }

	// pubk, _ := x509.MarshalPKIXPublicKey(publicKey)

	// log.Println(base64.RawStdEncoding.EncodeToString(pubk))

	blockId := getBlockId()

	gid, err := sign(blockId, privKey)
	if err != nil {
		log.Println(err)
	}

	blockIdArg := proto.NewStringArgument(blockId)
	rsaSign := proto.NewStringArgument(base64.StdEncoding.EncodeToString(gid))

	args.Append(blockIdArg)
	args.Append(rsaSign)

	// msg := []byte(blockId)

	// Before signing, we need to hash our message
	// The hash is what we actually sign
	// msgHash := sha256.New()
	// _, err = msgHash.Write(msg)
	// if err != nil {
	// 	panic(err)
	// }
	// msgHashSum := msgHash.Sum(nil)

	// err = rsa.VerifyPSS(publicKey.(*rsa.PublicKey), cr.SHA256, msgHashSum, gid, nil)
	// if err != nil {
	// 	log.Println("could not verify signature: ", err)
	// }
	// If we don't get any error from the `VerifyPSS` method, that means our
	// signature is valid
	// log.Println("signature verified")

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

func callMineIntent(miner string, amount uint64) error {
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
		Amount: amount,
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

func getMiners() proto.DataEntries {
	cl, err := client.NewClient(client.Options{BaseUrl: AnoteNodeURL, Client: &http.Client{}})
	if err != nil {
		log.Println(err)
	}

	addr := proto.MustAddressFromString(AtcAddr)
	adp := client.WithMatches("^miner_.*$")

	data, _, err := cl.Addresses.AddressesData(context.Background(), addr, adp)
	if err != nil {
		log.Println(err)
	}

	return data
}

func prettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
}

func parseMiner(de proto.DataEntry) (int64, int64) {
	start := int64(0)
	end := int64(0)
	v := de.ToProtobuf().GetStringValue()

	s := parseItem(v, 1)
	start = int64(s.(int))

	e := parseItem(v, 2)
	end = int64(e.(int))

	return start, end
}
