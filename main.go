package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"

	// 引入自建的Tron gRPC SDK仓库
	"github.com/qukuan/go-tron-grpc-sdk/api"
	"github.com/qukuan/go-tron-grpc-sdk/core"
)



// 日志级别
const (
	LevelDebug = iota
	LevelInfo
	LevelWarn
	LevelError
)



// 配置区域
const (
	// gRPC、API Key、Redis配置、测试监听地址
	TargetURL         = "grpc.trongrid.io:50051"
	TronGridApiKey    = "Trongrid-API-Key"
	RedisHost         = "127.0.0.1:6379"
	RedisPassword     = "redis_password"
	RedisDB           = 8
	MonitorAddressStr = "T123456789123456789" // 监听地址
	AppLogLevel       = LevelInfo

	// 合约地址，如果是Tron测试网环境则更改为相对应的测试网合约地址
	USDTContractAddress = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
	USDCContractAddress = "TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8"

	// Redis Keys
	RedisKeyMainBlock     = "tron:scanner:main_head"      // 主扫队列当前扫描高度
	RedisKeyBackfillStart = "tron:scanner:backfill:start" // 反向回填补扫区块起点 
	RedisKeyBackfillEnd   = "tron:scanner:backfill:end"   // 反向回填补扫区块终点 

	// 运行参数
	// 主循环配置
	MainLoopInterval = 2500 * time.Millisecond // 主线程轮询间隔 (2.5秒)

	// 主扫队列 (MainQueue) 
	MainQueueWorkerCount = 5                     // 并发协程数
	MainQueueMaxRetries  = 3                     // 最大重试次数
	MainQueueRetrySleep  = 500 * time.Millisecond // 每次重试间隔0.5秒

	// 重扫队列 (RescanQueue) 
	RescanQueueWorkerCount = 5                     // 并发协程数
	RescanQueueMaxRetries  = 3                     // 最大重试次数
	RescanQueueRetrySleep  = 500 * time.Millisecond // 每次重试间隔0.5秒

	// 反向回填补扫队列 (BackfillQueue) 
	BackfillQueueMaxRetries       = 5                // 最大重试次数
	BackfillQueueRetrySleep       = 1 * time.Second  // 每次重试间隔
	BackfillQueuePostProcessSleep = 3 * time.Second  // 每个块处理完后的固定休眠3秒
	MaxBackfillBlocks             = 100              // 最大反向回填补扫区块数量 

	// 业务订单消费队列 (BusinessQueue) 
	BusinessQueueWorkerCount = 1 // 业务队列消费线程
)


// Gas Free 相关
var (
	gasFreeUsdtTokenAddress = []byte{0xa6, 0x14, 0xf8, 0x03, 0xb6, 0xfd, 0x78, 0x09, 0x86, 0xa4, 0x2c, 0x78, 0xec, 0x9c, 0x7f, 0x77, 0xe6, 0xde, 0xd1, 0x3c}
	gasFreeOwnerAddress     = []byte{0x41, 0x3b, 0x41, 0x50, 0x50, 0xb1, 0xe7, 0x9e, 0x38, 0x50, 0x7c, 0xb6, 0xe4, 0x8d, 0xac, 0xc2, 0x27, 0xaf, 0xfd, 0xd5, 0x0c}
	gasFreeContractAddress  = []byte{0x41, 0x39, 0xdd, 0x12, 0xa5, 0x4e, 0x2b, 0xab, 0x7c, 0x82, 0xaa, 0x14, 0xa1, 0xe1, 0x58, 0xb3, 0x42, 0x63, 0xd2, 0xd5, 0x10}
)



// 2. 全局变量
var (
	rdb               *redis.Client
	grpcConn          *grpc.ClientConn
	grpcClient        api.WalletClient
	connMu            sync.RWMutex
	monitorAddressHex []byte
	usdtContractHex   []byte
	usdcContractHex   []byte
	logger            *log.Logger

	// 队列定义
	mainQueue     chan int64        // 主扫队列
	rescanQueue   chan int64        // 重扫队列
	backfillQueue chan int64        // 反向回填补扫队列
	businessQueue chan TransferInfo // 业务订单消费队列
)



func initLogger() {
	logger = log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)
}

func LogDebug(format string, v ...interface{}) {
	if AppLogLevel <= LevelDebug {
		logger.Printf("[DEBUG] "+format, v...)
	}
}

func LogInfo(format string, v ...interface{}) {
	if AppLogLevel <= LevelInfo {
		logger.Printf("[INFO]  "+format, v...)
	}
}

func LogWarn(format string, v ...interface{}) {
	if AppLogLevel <= LevelWarn {
		logger.Printf("[WARN]  "+format, v...)
	}
}

func LogError(format string, v ...interface{}) {
	if AppLogLevel <= LevelError {
		logger.Printf("[ERROR] "+format, v...)
	}
}



// 3. 工具函数
func DoubleHashB(b []byte) []byte {
	first := sha256.Sum256(b)
	second := sha256.Sum256(first[:])
	return second[:]
}


func CheckEncode(input []byte) string {
	b := make([]byte, 0, len(input)+4)
	b = append(b, input...)
	cksum := DoubleHashB(b)
	b = append(b, cksum[:4]...)
	return base58.Encode(b)
}


func DecodeAddress(addr string) ([]byte, error) {
	decoded, ver, err := base58.CheckDecode(addr)
	if err != nil {
		return nil, err
	}
	return append([]byte{ver}, decoded...), nil
}


func EncodeAddress(input []byte) string {
	if len(input) == 0 {
		return ""
	}
	return CheckEncode(input)
}



// apiKeyInterceptor 用于 gRPC 认证
type apiKeyInterceptor struct {
	apiKey string
}


func (aki *apiKeyInterceptor) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"TRON-PRO-API-KEY": aki.apiKey,
	}, nil
}


func (aki *apiKeyInterceptor) RequireTransportSecurity() bool {
	return false
}


// GetClient 获取 gRPC 客户端 (Insecure)
func GetClient() api.WalletClient {
	connMu.RLock()
	if grpcConn != nil && grpcConn.GetState() == connectivity.Ready {
		defer connMu.RUnlock()
		return grpcClient
	}
	connMu.RUnlock()

	connMu.Lock()
	defer connMu.Unlock()

	if grpcConn != nil && grpcConn.GetState() == connectivity.Ready {
		return grpcClient
	}

	if grpcConn != nil {
		grpcConn.Close()
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(1024 * 1024 * 64)),
		grpc.WithPerRPCCredentials(&apiKeyInterceptor{apiKey: TronGridApiKey}),
	}

	conn, err := grpc.Dial(TargetURL, opts...)
	if err != nil {
		LogError("gRPC 连接失败: %v", err)
		return nil
	}

	grpcConn = conn
	grpcClient = api.NewWalletClient(conn)
	LogDebug("gRPC 连接已重建 (Insecure): %s", TargetURL)
	return grpcClient
}



// 4. 核心业务逻辑
type TransactionType string

const (
	TxTypeTRX              TransactionType = "TRX_TRANSFER"
	TxTypeTRC20            TransactionType = "TRC20_TRANSFER"
	TxTypeResourceDelegate TransactionType = "RESOURCE_DELEGATE"
	TxTypeResourceReclaim  TransactionType = "RESOURCE_RECLAIM"
)

// TransferInfo 结构体
type TransferInfo struct {
	TxHash       string
	BlockNum     int64
	Timestamp    int64
	Type         TransactionType
	Token        string
	From         string
	To           string
	Amount       *big.Int
	Status       string  // 二次确认成功SUCCESS / 失败FAILED
	ResourceCode string
}



// ProcessBlock 解析区块 -> 验证 -> 投递到业务队列
func ProcessBlock(blockNum int64) error {
	client := GetClient()
	if client == nil {
		return fmt.Errorf("gRPC 客户端未就绪")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	block, err := client.GetBlockByNum2(ctx, &api.NumberMessage{Num: blockNum})
	if err != nil {
		return fmt.Errorf("获取区块 %d 失败: %v", blockNum, err)
	}

	if block == nil || block.BlockHeader == nil {
		return fmt.Errorf("获取的区块为空: %d", blockNum)
	}

	timestamp := block.BlockHeader.RawData.Timestamp

	for _, tx := range block.Transactions {
		// 顶层结果初步判断 (trans.Result.Result)
		// 如果顶层为 false，意味着交易连打包都失败了，直接跳过
		if !tx.Result.Result {
			continue
		}

		txHash := hex.EncodeToString(tx.Txid)
		rawData := tx.Transaction.RawData

		for _, contract := range rawData.Contract {
			var matchedInfo *TransferInfo

			switch contract.Type {
			case core.Transaction_Contract_TransferContract:
				// 解析原生币TRX
				matchedInfo = parseTrxTransfer(contract, txHash, timestamp, blockNum)

			case core.Transaction_Contract_TriggerSmartContract:
				// 解析智能合约（TRC20等）
				matchedInfo = parseSmartContract(contract, txHash, timestamp, blockNum)

			case core.Transaction_Contract_DelegateResourceContract:
				// 解析资源抵押
				matchedInfo = parseResourceDelegate(contract, txHash, timestamp, blockNum)

			case core.Transaction_Contract_UnDelegateResourceContract:
				// 解析资源赎回
				matchedInfo = parseResourceUnDelegate(contract, txHash, timestamp, blockNum)
			}

			// 如果解析出符合我们模型的交易，并且与监控地址相关
			if matchedInfo != nil && isMatchMonitor(matchedInfo) {
				// 进行二次上链确认
				if VerifyAndConfirmWithRetry(matchedInfo) {
					// 只有二次确认成功的交易才投递到业务队列
					select {
					case businessQueue <- *matchedInfo:
						LogInfo("✅ 交易最终确认并投递至业务队列: %s", txHash)
					default:
						LogError("业务订单队列已满! 交易可能丢失: %s", txHash)
					}
				}
			}
		}
	}
	return nil
}



func isMatchMonitor(info *TransferInfo) bool {
	return info.From == MonitorAddressStr || info.To == MonitorAddressStr
}



// 解析函数群
// parseTrxTransfer 解析原生TRX交易数据
func parseTrxTransfer(contract *core.Transaction_Contract, txHash string, ts, blockNum int64) *TransferInfo {
	var param core.TransferContract
	if err := contract.Parameter.UnmarshalTo(&param); err != nil {
		LogDebug("反序列化 TransferContract 失败: %v", err)
		return nil
	}

	return &TransferInfo{
		TxHash:    txHash,
		BlockNum:  blockNum,
		Timestamp: ts,
		Type:      TxTypeTRX,
		Token:     "TRX",
		From:      EncodeAddress(param.OwnerAddress),
		To:        EncodeAddress(param.ToAddress),
		Amount:    big.NewInt(param.Amount),
	}
}



// parseSmartContract 智能合约解析函数
func parseSmartContract(contract *core.Transaction_Contract, txHash string, ts, blockNum int64) *TransferInfo {
	var param core.TriggerSmartContract
	if err := contract.Parameter.UnmarshalTo(&param); err != nil {
		LogDebug("反序列化 TriggerSmartContract 失败: %v", err)
		return nil
	}

	contractAddr := param.ContractAddress
	data := param.Data

	// 1. 优先处理特殊的 "Gas Free" 业务
	if bytes.Equal(param.OwnerAddress, gasFreeOwnerAddress) && bytes.Equal(contractAddr, gasFreeContractAddress) {
		// 验证方法签名和数据长度
		if len(data) == 420 && bytes.Equal(data[:4], []byte{0x6f, 0x21, 0xb8, 0x98}) {
			if !bytes.Equal(data[16:36], gasFreeUsdtTokenAddress) {
				return nil // 检查内嵌的token地址是否为USDT
			}
			user := CheckEncode(append([]byte{0x41}, data[48:68]...))
			receiver := CheckEncode(append([]byte{0x41}, data[80:100]...))
			amount := new(big.Int).SetBytes(data[100:132])
			
			return &TransferInfo{
				TxHash:    txHash, BlockNum: blockNum, Timestamp: ts,
				Type:      TxTypeTRC20,
				Token:     "USDT-GasFree",
				From:      user,
				To:        receiver,
				Amount:    amount,
			}
		}
	}

	// 2. 处理常规 TRC20 (USDT, USDC) 智能合约交易
	var tokenSymbol string
	isKnownTRC20 := false
	if bytes.Equal(contractAddr, usdtContractHex) {
		tokenSymbol = "USDT"
		isKnownTRC20 = true
	} else if bytes.Equal(contractAddr, usdcContractHex) {
		tokenSymbol = "USDC"
		isKnownTRC20 = true
	}

	if !isKnownTRC20 {
		return nil // 不是我们监控的TRC20合约，直接返回
	}

	if len(data) < 4 {
		return nil // 数据长度不足，无法解析
	}
	methodSig := data[:4]

	// 情况 A: transfer(address,uint256) - a9059cbb
	if bytes.Equal(methodSig, []byte{0xa9, 0x05, 0x9c, 0xbb}) {
		// 严格验证数据长度
		if len(data) != 68 {
			LogDebug("Tx %s: transfer 方法数据长度不匹配, 期望 68, 实际 %d", txHash, len(data))
			return nil
		}
		to := CheckEncode(append([]byte{0x41}, data[16:36]...))
		amount := new(big.Int).SetBytes(data[36:68])
		return &TransferInfo{
			TxHash:    txHash, BlockNum: blockNum, Timestamp: ts,
			Type:      TxTypeTRC20,
			Token:     tokenSymbol,
			From:      EncodeAddress(param.OwnerAddress),
			To:        to,
			Amount:    amount,
		}
	}

	// 情况 B: transferFrom(address,address,uint256) - 23b872dd
	if bytes.Equal(methodSig, []byte{0x23, 0xb8, 0x72, 0xdd}) {
		// 严格验证数据长度
		if len(data) != 100 {
			LogDebug("Tx %s: transferFrom 方法数据长度不匹配, 期望 100, 实际 %d", txHash, len(data))
			return nil
		}
		from := CheckEncode(append([]byte{0x41}, data[16:36]...))
		to := CheckEncode(append([]byte{0x41}, data[48:68]...))
		amount := new(big.Int).SetBytes(data[68:100])
		return &TransferInfo{
			TxHash:    txHash, BlockNum: blockNum, Timestamp: ts,
			Type:      TxTypeTRC20,
			Token:     tokenSymbol,
			From:      from,
			To:        to,
			Amount:    amount,
		}
	}

	return nil // 其他未知方法，不处理
}



// parseResourceDelegate 解析资源抵押
func parseResourceDelegate(contract *core.Transaction_Contract, txHash string, ts, blockNum int64) *TransferInfo {
	var param core.DelegateResourceContract
	if err := contract.Parameter.UnmarshalTo(&param); err != nil {
		return nil
	}
	// 抵押给自己或0余额的抵押没有意义，可以过滤
	if bytes.Equal(param.OwnerAddress, param.ReceiverAddress) || param.Balance == 0 {
		return nil
	}
	return &TransferInfo{
		TxHash:       txHash, BlockNum: blockNum, Timestamp: ts,
		Type:         TxTypeResourceDelegate,
		Token:        "RESOURCE",
		ResourceCode: param.Resource.String(),
		From:         EncodeAddress(param.OwnerAddress),
		To:           EncodeAddress(param.ReceiverAddress),
		Amount:       big.NewInt(param.Balance),
	}
}



// parseResourceUnDelegate 解析资源赎回
func parseResourceUnDelegate(contract *core.Transaction_Contract, txHash string, ts, blockNum int64) *TransferInfo {
	var param core.UnDelegateResourceContract
	if err := contract.Parameter.UnmarshalTo(&param); err != nil {
		return nil
	}
	if param.Balance == 0 {
		return nil
	}
	return &TransferInfo{
		TxHash:       txHash, BlockNum: blockNum, Timestamp: ts,
		Type:         TxTypeResourceReclaim,
		Token:        "RESOURCE",
		ResourceCode: param.Resource.String(),
		From:         EncodeAddress(param.OwnerAddress),
		// 赎回时，接收方就是自己
		To:           EncodeAddress(param.OwnerAddress), 
		Amount:       big.NewInt(param.Balance),
	}
}



// VerifyAndConfirmWithRetry 区分TRX原生币跟合约代币的二次确认
func VerifyAndConfirmWithRetry(info *TransferInfo) bool {
	maxRetries := 3
	sleepDuration := 500 * time.Millisecond

	for i := 0; i < maxRetries; i++ {
		client := GetClient()
		if client == nil {
			LogWarn("二次确认失败 (gRPC Client不可用)，第 %d 次重试...", i+1)
			time.Sleep(sleepDuration)
			continue
		}

		txHashBytes, err := hex.DecodeString(info.TxHash)
		if err != nil {
			LogError("二次确认失败：哈希格式错误 %s", info.TxHash)
			return false // 格式错误，无需重试
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

		// 根据交易类型选择不同的验证方法 
		if info.Type == TxTypeTRX || info.Type == TxTypeResourceDelegate || info.Type == TxTypeResourceReclaim {
			// 1. 原生交易 (TRX, 资源等): 使用 GetTransactionById
			tx, err := client.GetTransactionById(ctx, &api.BytesMessage{Value: txHashBytes})
			if err != nil {
				LogWarn("二次确认(原生)网络波动 [%s] 第 %d 次重试... 错误: %v", info.TxHash, i+1, err)
				cancel()
				time.Sleep(sleepDuration)
				continue
			}

			if tx != nil && len(tx.GetRet()) > 0 {
				if tx.GetRet()[0].GetContractRet() == core.Transaction_Result_SUCCESS {
					info.Status = "SUCCESS"
					LogDebug("二次确认成功 [%s]", info.TxHash)
					cancel()
					return true // 明确成功
				} else {
					info.Status = "FAILED"
					LogWarn("二次确认发现原生交易执行失败 [%s] 状态: %s", info.TxHash, tx.GetRet()[0].GetContractRet().String())
					cancel()
					return false // 明确失败, 无需重试
				}
			}
			// 如果 tx 为 nil 或 GetRet() 为空，则视为未找到，将继续重试
		} else {
			// 2. TRC20/合约代币 (USDT, USDC, GasFree): 使用 GetTransactionInfoById
			txInfo, err := client.GetTransactionInfoById(ctx, &api.BytesMessage{Value: txHashBytes})
			if err != nil {
				LogWarn("二次确认(合约)网络波动 [%s] 第 %d 次重试... 错误: %v", info.TxHash, i+1, err)
				cancel()
				time.Sleep(sleepDuration)
				continue
			}

			if txInfo != nil && txInfo.GetReceipt() != nil {
				if txInfo.GetReceipt().GetResult() == core.Transaction_Result_SUCCESS {
					info.Status = "SUCCESS"
					LogDebug("二次确认成功 [%s]", info.TxHash)
					cancel()
					return true // 明确成功
				} else {
					info.Status = "FAILED"
					LogWarn("二次确认发现合约交易执行失败 [%s] 状态: %s", info.TxHash, txInfo.GetReceipt().GetResult().String())
					cancel()
					return false // 明确失败, 无需重试
				}
			}
			// 如果 txInfo 或 Receipt 为 nil，则视为未找到，将继续重试
		}

		cancel() // 确保在重试前释放上下文
		// 如果交易未找到，休眠后重试
		LogWarn("二次确认未找到交易信息 [%s]，第 %d 次重试...", info.TxHash, i+1)
		time.Sleep(sleepDuration)
	}

	LogWarn("二次确认最终失败 (超时或重试耗尽) [%s]", info.TxHash)
	return false
}



// 打印交易日志 (业务订单消费队列调用)
func LogMatchedTransaction(t TransferInfo) {
	direction := "UNKNOWN"
	if t.To == MonitorAddressStr {
		direction = "IN (收款)"
	} else if t.From == MonitorAddressStr {
		direction = "OUT (付款)"
	}

	var displayAmount string
	if t.Token == "TRX" || t.Token == "RESOURCE" {
		fAmount := new(big.Float).SetInt(t.Amount)
		fAmount.Quo(fAmount, big.NewFloat(1000000))
		displayAmount = fAmount.Text('f', 6)
	} else if strings.HasPrefix(t.Token, "USDT") || strings.HasPrefix(t.Token, "USDC") {
		fAmount := new(big.Float).SetInt(t.Amount)
		fAmount.Quo(fAmount, big.NewFloat(1000000))
		displayAmount = fAmount.Text('f', 6)
	} else {
		displayAmount = t.Amount.String()
	}

	typeStr := string(t.Type)
	if t.Type == TxTypeResourceDelegate || t.Type == TxTypeResourceReclaim {
		typeStr = fmt.Sprintf("%s (%s)", t.Type, t.ResourceCode)
	}

	msg := fmt.Sprintf("\n"+
		"╔══════════════════════════════════════════════════════════════╗\n"+
		"║ 🔔 交易确认成功 (Verified & Queued)                          ║\n"+
		"╠══════════════════════════════════════════════════════════════╣\n"+
		"║ 类型:   %-52s ║\n"+
		"║ 方向:   %-52s ║\n"+
		"║ 哈希:   %-52s ║\n"+
		"║ 币种:   %-52s ║\n"+
		"║ 数量:   %-52s ║\n"+
		"║ 发送方: %-52s ║\n"+
		"║ 接收方: %-52s ║\n"+
		"║ 时间:   %-52s ║\n"+
		"╚══════════════════════════════════════════════════════════════╝",
		typeStr, direction, t.TxHash, t.Token, displayAmount, t.From, t.To,
		time.Unix(t.Timestamp/1000, 0).Format("2006-01-02 15:04:05"))

	logger.Println(msg)
}




// ProcessWithCustomRetry 重试机制函数 (支持自定义重试参数)
func ProcessWithCustomRetry(blockNum int64, queueTag string, maxRetries int, sleepDur time.Duration, isFatal bool) bool {
	for i := 0; i < maxRetries; i++ {
		err := ProcessBlock(blockNum)
		if err == nil {
			LogInfo("[%s] 区块 %d 处理完成 ✅", queueTag, blockNum)
			return true
		}
		// 只有在非最后一次重试时才休眠
		if i < maxRetries-1 {
			time.Sleep(sleepDur)
		}
	}

	if isFatal {
		LogError("[%s] 区块 %d 达到最大重试次数，已放弃 ❌", queueTag, blockNum)
	} else {
		LogWarn("[%s] 区块 %d 处理失败 -> 移交下一级", queueTag, blockNum)
	}
	return false
}




// 主函数
func main() {
	// 忽略 TLS 证书校验
	httpTransport := &tls.Config{InsecureSkipVerify: true}
	_ = httpTransport

	initLogger()

	// 1. 初始化 Redis
	rdb = redis.NewClient(&redis.Options{
		Addr:     RedisHost,
		Password: RedisPassword,
		DB:       RedisDB,
	})

	if _, err := rdb.Ping(context.Background()).Result(); err != nil {
		log.Fatalf("Redis 连接失败: %v", err)
	}
	LogInfo("Redis 连接成功")

	// 2. 预处理地址
	var err error
	monitorAddressHex, err = DecodeAddress(MonitorAddressStr)
	if err != nil {
		log.Fatalf("监听地址无效: %v", err)
	}
	usdtContractHex, err = DecodeAddress(USDTContractAddress)
	if err != nil {
		log.Fatalf("USDT地址无效: %v", err)
	}
	usdcContractHex, err = DecodeAddress(USDCContractAddress)
	if err != nil {
		log.Fatalf("USDC地址无效: %v", err)
	}

	// 3. 初始化队列
	mainQueue = make(chan int64, 200)
	rescanQueue = make(chan int64, 200)
	backfillQueue = make(chan int64, 200)
	businessQueue = make(chan TransferInfo, 200)

	var wg sync.WaitGroup

	// 4. 启动业务订单消费队列 
	wg.Add(BusinessQueueWorkerCount)
	go func() {
		defer wg.Done()
		LogInfo("业务订单消费队列已启动...")
		for info := range businessQueue {
			LogMatchedTransaction(info)
		}
	}()

	// 5. 启动主扫队列
	for i := 0; i < MainQueueWorkerCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for blockNum := range mainQueue {
				// 主扫队列：失败则返回false，将任务移交至重扫队列
				if !ProcessWithCustomRetry(blockNum, fmt.Sprintf("Main-%d", id), MainQueueMaxRetries, MainQueueRetrySleep, false) {
					rescanQueue <- blockNum
				}
			}
		}(i)
	}

	// 6. 启动重扫队列
	for i := 0; i < RescanQueueWorkerCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for blockNum := range rescanQueue {
				// 重扫队列：失败则Fatal(记录日志并丢弃)
				ProcessWithCustomRetry(blockNum, fmt.Sprintf("Rescan-%d", id), RescanQueueMaxRetries, RescanQueueRetrySleep, true)
			}
		}(i)
	}

	// 7. 启动反向回填补扫队列
	wg.Add(1)
	go func() {
		defer wg.Done()
		LogInfo("反向补扫队列消费者已启动...")
		for blockNum := range backfillQueue {
			// 反向回填补扫队列：重试后失败则记录日志丢弃，无论成功失败都固定休眠
			ProcessWithCustomRetry(blockNum, "Backfill-0", BackfillQueueMaxRetries, BackfillQueueRetrySleep, true)
			LogDebug("[Backfill-0] 区块 %d 处理完毕，固定休眠 %v...", blockNum, BackfillQueuePostProcessSleep)
			time.Sleep(BackfillQueuePostProcessSleep)
		}
	}()

	// 8. 启动区块生产者 (包含反向补扫计算 + 主循环)
	go func() {
		ctx := context.Background()
		var lastDispatchedHeight int64 = 0

		// A. 启动/重启逻辑：计算断点和漏块
		LogInfo("🚀 系统启动，正在初始化区块高度...")
		for {
			client := GetClient()
			if client == nil {
				time.Sleep(2 * time.Second)
				continue
			}

			nowBlock, err := client.GetNowBlock2(ctx, &api.EmptyMessage{})
			if err != nil {
				LogError("初始化获取最新区块失败: %v", err)
				time.Sleep(2 * time.Second)
				continue
			}
			currentHeight := nowBlock.BlockHeader.RawData.Number

			lastDispatchedHeight = currentHeight - 1 // 默认从当前块的前一个块开始

			// 读取历史断点
			redisLastVal, err := rdb.Get(ctx, RedisKeyMainBlock).Int64()
			if err == nil && redisLastVal > 0 {
				gap := currentHeight - redisLastVal
				LogInfo("发现历史断点: %d, 当前最新: %d, 差距: %d", redisLastVal, currentHeight, gap)

				if gap > 0 {
					startScan := redisLastVal + 1
					// 限制最大补扫数量
					if gap > MaxBackfillBlocks {
						LogWarn("差距过大 (>%d)，将截断补扫范围", MaxBackfillBlocks)
						startScan = currentHeight - MaxBackfillBlocks + 1
					}

					// 记录补扫范围到 Redis (仅作记录)
					rdb.Set(ctx, RedisKeyBackfillStart, startScan, 0)
					rdb.Set(ctx, RedisKeyBackfillEnd, currentHeight, 0)
					LogInfo(">>> 开始反向补扫任务: [%d -> %d] (共 %d 块)", startScan, currentHeight, currentHeight-startScan+1)

					// 异步投递补扫任务，不阻塞主流程
					go func(start, end int64) {
						for b := start; b <= end; b++ {
							backfillQueue <- b
						}
					}(startScan, currentHeight)

					// 补扫期间，主线程指针直接跳到最新
					lastDispatchedHeight = currentHeight
				} else {
					// 如果没有差距，也从历史断点开始
					lastDispatchedHeight = redisLastVal
				}
			} else {
				LogInfo("无有效历史断点，从当前最新高度的前一个高度开始: %d", lastDispatchedHeight)
			}

			// 更新当前主线程高度 Key
			rdb.Set(ctx, RedisKeyMainBlock, lastDispatchedHeight, 0)
			break
		}

		// B. 主线程持续轮询
		ticker := time.NewTicker(MainLoopInterval)
		defer ticker.Stop()

		for range ticker.C {
			client := GetClient()
			if client == nil {
				continue
			}

			nowBlock, err := client.GetNowBlock2(ctx, &api.EmptyMessage{})
			if err != nil {
				LogError("轮询失败: %v", err)
				continue
			}

			currentHeight := nowBlock.BlockHeader.RawData.Number

			// 如果有新块
			if currentHeight > lastDispatchedHeight {

				// 检查判断获取到的最新区块
				// 逻辑：
				// 1. lastDispatchedHeight + 1 到 currentHeight - 1 之间的块 -> 视为漏块 (Gap)，推入 反向回填补扫队列BackfillQueue
				// 2. currentHeight (最新块) -> 推入 主队列MainQueue
				if currentHeight-lastDispatchedHeight > 1 {
					LogWarn("⚠️ 发现区块漏块区间: %d -> %d (Gap: %d)",
						lastDispatchedHeight, currentHeight, currentHeight-lastDispatchedHeight-1)
				}

				for i := lastDispatchedHeight + 1; i <= currentHeight; i++ {
					// 判断是否为最新块
					isLatest := (i == currentHeight)

					if !isLatest {
						// 漏块逻辑 (小于 currentHeight) 
						select {
						case backfillQueue <- i:
							LogInfo(" -> [Backfill] 漏块 %d 已推入反向补扫队列", i)
						default:
							// 如果补扫队列满，记录错误但继续循环，不阻塞主线程
							LogError("反向补扫队列已满! 漏块 %d 无法推入 (丢失)", i)
						}
						// 继续处理下一个块
						continue
					}

					// 最新块逻辑 (i == currentHeight) 
					select {
					case mainQueue <- i:
						// 成功投递
					default:
						LogWarn("主队列已满，区块 %d 暂时无法投递!", i)
						// 当队列满时，我们应该停止投递并等待下一次 ticker
						// 更新 lastDispatchedHeight 到最后一个成功投递的块 (即 i-1)
						lastDispatchedHeight = i - 1
						// 强制更新 Redis，避免丢失进度 (但漏块已经推入了backfill)
						rdb.Set(ctx, RedisKeyMainBlock, lastDispatchedHeight, 0)
						// 跳出内部 for 循环
						goto nextTicker
					}
				}

				// 所有块都处理完毕 (漏块进了 Backfill，最新块进了 Main)
				lastDispatchedHeight = currentHeight
				// 更新 Redis
				rdb.Set(ctx, RedisKeyMainBlock, lastDispatchedHeight, 0)
			}
		nextTicker:
		}
	}()

	// 优雅退出
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	LogInfo("正在停止服务...")
	close(mainQueue)
	close(rescanQueue)
	close(backfillQueue)
	wg.Wait()            // 等待队列消费者处理完所有剩余任务
	close(businessQueue) // 确保业务队列在所有上游都关闭后再关闭
	LogInfo("服务已停止")
}







