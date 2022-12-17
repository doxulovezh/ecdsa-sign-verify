package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"github.com/Conflux-Chain/go-conflux-sdk/types/cfxaddress"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/middleware/logger"
	IrisRecover "github.com/kataras/iris/v12/middleware/recover"
)

var app *iris.Application

type heyfoologin_msg struct {
	Signlogin SignLogin `json:"signlogin"`
	R         string    `json:"r"`
	S         string    `json:"s"`
	V         string    `json:"v"`
	Publickey []byte    `json:"publickey"`
	Chaintype string    `json:"chaintype"`
}
type SignLogin struct {
	Domain     string `json:"domain"`
	Phone      string `json:"phone"`
	Address    string `json:"address"`
	Message    string `json:"message"`
	Expiration int64  `json:"expiration"`
}
type heyfoologin_reg struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}

// 错误处理
func PanicHandler() {
	exeName := os.Args[0]                                             //获取程序名称
	now := time.Now()                                                 //获取当前时间
	pid := os.Getpid()                                                //获取进程ID
	time_str := now.Format("20060102150405")                          //设定时间格式
	fname := fmt.Sprintf("%s-%d-%s-dump.log", exeName, pid, time_str) //保存错误信息文件名:程序名-进程ID-当前时间（年月日时分秒）
	fmt.Println("dump to file", fname)
	f, err := os.Create(fname)
	if err != nil {
		return
	}
	defer f.Close()
	if err := recover(); err != nil {
		f.WriteString(fmt.Sprintf("%v\r\n", err)) //输出panic信息
		f.WriteString("========\r\n")
	}
	f.WriteString(string(debug.Stack())) //输出堆栈信息
}
func todayFilename() string {
	today := time.Now().Format("Jan 02 2006")
	return today + ".txt"
}
func newLogFile() *os.File {
	filename := "./log/" + todayFilename()
	// Open the file, this will append to the today's file if server restarted.
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		panic(err)
	}

	return f
}
func main() {

	defer PanicHandler() // // 错误处理
	app = iris.New()
	app.Logger().SetLevel("error") //日志
	// 设置recover从panics恢复，设置log记录
	app.Use(logger.New())
	app.Use(IrisRecover.New())
	// 优雅的关闭程序
	serverWG := new(sync.WaitGroup)
	defer serverWG.Wait()
	iris.RegisterOnInterrupt(func() {
		serverWG.Add(1)
		defer serverWG.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		app.Shutdown(ctx)
		// 关闭全部主机
		for {
			fmt.Println("退出关闭,请输入exit")
			input := bufio.NewScanner(os.Stdin)
			input.Scan()
			code := input.Text()
			if code == "exit" {
				break
			}
		}
		app.Logger().Error("退出关闭")
		time.Sleep(1 * time.Second)
	})
	//通用
	app.Get("/test", test)
	app.Post("/heyfoologin", heyfoologin)

	fmt.Println("---------------------->>> 服务初始化成功!")
	app.Listen("127.0.0.1:6666", iris.WithoutServerError(iris.ErrServerClosed))
}

func test(ctx iris.Context) {
	ctx.WriteString("communication success!")
}
func heyfoologin(ctx iris.Context) {
	Msg := &heyfoologin_msg{}
	if err := ctx.ReadJSON(Msg); err != nil {
		var Res heyfoologin_reg
		Res.Code = -1
		Res.Msg = "ReadJSON 错误:" + err.Error()
		bu, _ := json.Marshal(Res)
		ctx.Write(bu)
		return
	} else {
		var Res heyfoologin_reg
		//失效时间检查，超过失效时间则抛弃。通常是60秒
		fmt.Println(time.Now().Unix(), Msg.Signlogin.Expiration)
		if time.Now().Unix() > Msg.Signlogin.Expiration {
			Res.Code = -1
			Res.Msg = "Time Expire"
			bu, _ := json.Marshal(Res)
			ctx.Write(bu)
			return
		}
		puk, err := GetPubK(Msg.Publickey)
		if err != nil {
			Res.Code = -1
			Res.Msg = err.Error()
			bu, _ := json.Marshal(Res)
			ctx.Write(bu)
			return
		}
		if !VerifyAddr(*puk, Msg.Signlogin.Address) {
			Res.Code = -1
			Res.Msg = "公钥与地址不匹配！"
			bu, _ := json.Marshal(Res)
			ctx.Write(bu)
			return
		}
		boo, err := VerifyHash(*Msg, Msg.V)
		if err != nil {
			Res.Code = -1
			Res.Msg = err.Error()
			bu, _ := json.Marshal(Res)
			ctx.Write(bu)
			return
		}
		if !boo {
			Res.Code = -1
			Res.Msg = "hash值错误"
			bu, _ := json.Marshal(Res)
			ctx.Write(bu)
			return
		}
		Bhash, err := hex.DecodeString(Msg.V)
		if err != nil {
			Res.Code = -1
			Res.Msg = err.Error()
			bu, _ := json.Marshal(Res)
			ctx.Write(bu)
			return
		}
		Br, _ := big.NewInt(0).SetString(Msg.R, 16)
		Bs, _ := big.NewInt(0).SetString(Msg.S, 16)

		Re := Verify(puk, Bhash, Br, Bs)
		fmt.Println("验证器：", Re)
		if Re {
			Res.Code = 0
			Res.Msg = "签名正确"
			bu, _ := json.Marshal(Res)
			ctx.Write(bu)
			return
		} else {
			Res.Code = -1
			Res.Msg = "签名错误"
			bu, _ := json.Marshal(Res)
			ctx.Write(bu)
			return
		}
	}
}

func GetPubK(pubdata []byte) (*ecdsa.PublicKey, error) {
	PRK, err := crypto.HexToECDSA("1c7c41fcc3e6bf976dedfcd1d137b8553bce3c48cebb9515774fc2ceed83471a")
	var target *ecdsa.PublicKey
	target = &PRK.PublicKey
	err = json.Unmarshal(pubdata, target)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	pk := ecies.ImportECDSAPublic(target)
	return pk.ExportECDSA(), nil
}

func Verify(pub *ecdsa.PublicKey, hash []byte, r *big.Int, s *big.Int) bool {
	// fmt.Println(hash, r, s)
	return ecdsa.Verify(pub, hash, r, s)

}

func VerifyAddr(puk ecdsa.PublicKey, cfxaddr string) bool {
	ADDRESS := crypto.PubkeyToAddress(puk)
	buff := []byte(ADDRESS.String())
	buff[2] = 49
	CFXADDR := cfxaddress.MustNewFromHex(string(buff), 1029)
	// fmt.Println("Accunt address:", CFXADDR.MustGetBase32Address(), cfxaddr)
	if cfxaddr == CFXADDR.MustGetBase32Address() {
		return true
	} else {
		return false
	}

}
func VerifyHash(msg heyfoologin_msg, hash string) (bool, error) {
	Da := msg.Signlogin
	buSignL, err := json.Marshal(Da)
	if err != nil {
		return false, err
	}
	Hd := sha256.Sum256(buSignL)
	Nh := hex.EncodeToString(Hd[:])
	if Nh == hash {
		return true, nil
	} else {
		return false, nil
	}
}
