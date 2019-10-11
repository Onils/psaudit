package utils

import (
    "bufio"
    "bytes"
    "fmt"
    "io"
    "log"
    "os"
    "path/filepath"
    "regexp"
    "strconv"
    "strings"
    "time"
)

func ReadLine(reader io.Reader, f func(string) error) error {
    buf := bufio.NewReader(reader)
    line, err := buf.ReadBytes('\n')
    for err == nil {
        line = bytes.TrimRight(line, "\n")
        if len(line) > 0 {
            if line[len(line)-1] == 13 { //'\r'
                line = bytes.TrimRight(line, "\r")
            }
            err = f(string(line))
            if err != nil {
                return err
            }
        }
        line, err = buf.ReadBytes('\n')
    }
    if len(line) > 0 {
        err = f(string(line))
    }
    if err != io.EOF {
        return err
    }
    return nil
}

func ReadLink(path string) string {
    info, err := os.Lstat(path)
    if err != nil {
        return path
    }
    if strings.HasPrefix(info.Mode().String(), "L") {
        dstPath, err := os.Readlink(path)
        if err != nil {
            return path
        }
        if strings.HasPrefix(dstPath, "/") {
            return dstPath
        }
        absDstPath := filepath.Join(filepath.Dir(path), dstPath)
        return absDstPath
    }
    return path
}


func SearchString(path string, regex string) []string {
    deadline := time.Now().Add(30 * time.Second)
    var ret []string
    if _, err := os.Stat(path); err != nil {
        return ret
    }
    f, err := os.Open(path)
    if err != nil {
        log.Fatal("open file err:", err)
        return ret
    }
    defer f.Close()

    reg, err := regexp.Compile(regex)
    if err != nil {
        return ret
    }
    _ = ReadLine(f, func(line string) error {
        if time.Now().After(deadline) {
            err = fmt.Errorf("timeout reached")
            log.Fatal("search string timeout:", path)
            return err
        }
        match := reg.FindStringSubmatch(line)
        if len(match) > 0 {
            ret = match
            return fmt.Errorf("break readline")
        }
        return nil
    })
    return ret
}

func Hex2Dec(h string) int64 {
    d,err := strconv.ParseInt(h,16,32)
    if err!=nil {
        d = int64(0)
    }
    return d
}


func ConvertIp(ip string) string {
    // Convert the ipv4 to decimal. Have to rearrange the ip because the
    // default value is in little Endian order.

    var out string

    // Check ip size if greater than 8 is a ipv6 type
    if len(ip) > 8 {
        i := []string{ip[30:32],
            ip[28:30],
            ip[26:28],
            ip[24:26],
            ip[22:24],
            ip[20:22],
            ip[18:20],
            ip[16:18],
            ip[14:16],
            ip[12:14],
            ip[10:12],
            ip[8:10],
            ip[6:8],
            ip[4:6],
            ip[2:4],
            ip[0:2]}
        out = fmt.Sprintf("%v%v:%v%v:%v%v:%v%v:%v%v:%v%v:%v%v:%v%v",
            i[14], i[15], i[13], i[12],
            i[10], i[11], i[8], i[9],
            i[6], i[7], i[4], i[5],
            i[2], i[3], i[0], i[1])

    } else {
        i := []int64{Hex2Dec(ip[6:8]),
            Hex2Dec(ip[4:6]),
            Hex2Dec(ip[2:4]),
            Hex2Dec(ip[0:2])}

        out = fmt.Sprintf("%v.%v.%v.%v", i[0], i[1], i[2], i[3])
    }
    return out
}