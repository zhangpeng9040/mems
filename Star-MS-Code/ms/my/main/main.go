package main

import (
	"fmt"

	"github.com/360EntSecGroup-Skylar/excelize/v2"
)


func main() {
	f, err1 := excelize.OpenFile("temp.xlsx")
	if err1 != nil {
		fmt.Println(err1)
	}
	
	col := "c"
	index := f.NewSheet("demo1")
	f.SetCellValue("demo1", col+"1", "Hllo")
	f.SetCellValue("Sheet2", col+"2", float64(569498456)/10.0)
	f.SetActiveSheet(index)
	if err := f.Save(); err != nil {
		fmt.Println(err)
	}
}