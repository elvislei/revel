package revel

import (
	"fmt"
	"time"
)

//输出每一个被调用的Action执行所花费的时间
func CosTimeFilter(c *Controller, fc []Filter) {
	bTime := time.Now()
	fc[0](c, fc[1:])
	usedTime := time.Since(bTime)

	//TODO:是否能获取到Controller的文件名与路径
	if "Static" != c.Name { //去掉static模块的输出
		fmt.Printf("DEBUG %v action:%s costime:%v \n", time.Now().Format("2006/01/02 15:04:05"), c.Action, usedTime)
	}

}
