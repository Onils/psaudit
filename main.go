package main

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "os"
    "os/signal"
    "path/filepath"
    "psaudit/psnotify"
    "psaudit/utils"
    "regexp"
    "strconv"
    "strings"
    "syscall"
)


type Proc struct {
    Name     string `json:"name"`
    Cmd      string `json:"cmd"`
    Pid      int    `json:"pid"`
    State    string `json:"state"`
    Tgid     int    `json:"tgid"`
    Uid      string `json:"uid"`
    Euid     int    `json:"euid"`
    Suid     int    `json:"suid"`
    Fsuid    int    `json:"fsuid"`
    Gid      string `json:"gid"`
    Egid     int    `json:"egid"`
    Sgid     int    `json:"sgid"`
    Fsgid    int    `json:"fsgid"`
    Cwd      string `json:"cwd"`
    Exe      string `json:"exe"`
    Ppid     int    `json:"ppid"`
    PName    string `json:"p_name"`
    PUid     string `json:"p_uid"`
    PCmd     string `json:"p_cmd"`
    FdInfo   string `json:"fd_info"`
    SockInfo string `json:"sock_info"`
}




var ProtoFile = map[string]string{
    "tcp":  "/proc/net/tcp",
    "udp":  "/proc/net/udp",
    "unix": "/proc/net/unix",
}
var Net = []string{"tcp", "udp", "unix"}

func readProcess(pid int) string {
    pInfo := &Proc{
        Pid: pid,
    }


    //read /proc/PID/status
    f, err := os.Open(fmt.Sprintf("/proc/%d/status", pInfo.Pid))
    if err != nil {
        return ""
    }
    _ = utils.ReadLine(f, func(line string) error {
        info := strings.SplitN(line, ":", 2)
        if len(info) != 2 {
            return nil
        }
        switch info[0] {
        case "Name":
            pInfo.Name = strings.TrimSpace(info[1])
        case "State":
            pInfo.State = strings.TrimSpace(info[1])
        case "Tgid":
            pInfo.Tgid, _ = strconv.Atoi(strings.TrimSpace(info[1]))
        case "PPid":
            pInfo.Ppid, _ = strconv.Atoi(strings.TrimSpace(info[1]))
        case "Uid":
            uids := strings.SplitN(strings.TrimSpace(info[1]), "\t", 4)
            if len(uids) != 4 {
                break
            }
            pInfo.Uid = fmt.Sprintf("%s(%s)", uids[0], uid2Name(uids[0]))
            pInfo.Euid, _ = strconv.Atoi(uids[1])
            pInfo.Suid, _ = strconv.Atoi(uids[2])
            pInfo.Fsuid, _ = strconv.Atoi(uids[3])
        case "Gid":
            gids := strings.SplitN(strings.TrimSpace(info[1]), "\t", 4)
            if len(gids) != 4 {
                break
            }
            pInfo.Gid = fmt.Sprintf("%s(%s)", gids[0], gid2Group(gids[0]))
            pInfo.Egid, _ = strconv.Atoi(gids[1])
            pInfo.Sgid, _ = strconv.Atoi(gids[2])
            pInfo.Fsgid, _ = strconv.Atoi(gids[3])
            return fmt.Errorf("break readline")
        }
        return nil
    })
    f.Close()
    pInfo.Cwd = getProcCwd(pInfo.Pid)
    pInfo.Cmd = getProcCmd(pInfo.Pid)
    pInfo.Exe = getProcExe(pInfo.Pid)
    pInfo.PName, pInfo.PUid = getProcInfo(pInfo.Ppid)
    pInfo.PCmd = getProcCmd(pInfo.Ppid)
    pInfo.FdInfo, pInfo.SockInfo = getProcFd(pInfo.Pid)
    //pInfo["env"] = getProcEnv(pInfo["pid"])

    pInfoJson, _ := json.MarshalIndent(pInfo, "", "      ")

    return string(pInfoJson)
}

func getProcCwd(pid int) string {
    var cwd string
    match := utils.SearchString(fmt.Sprintf("/proc/%d/environ", pid), `\0PWD=([^\s\0]+)`)
    if len(match) > 1 {
        cwd = match[1]
    }
    return cwd
}

func getProcCmd(pid int) string {
    content, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
    if err != nil {
        return ""
    }
    return strings.Join(strings.Split(string(content), "\u0000"), " ")
}

func getProcInfo(pid int) (string, string) {
    var pName, pUid string

    f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
    if err != nil {
        return "", ""
    }
    defer f.Close()
    _ = utils.ReadLine(f, func(line string) error {
        info := strings.SplitN(line, ":", 2)
        if len(info) == 2 {
            switch info[0] {
            case "Name":
                pName = strings.TrimSpace(info[1])
            case "Uid":
                pUid = strings.SplitN(strings.TrimSpace(info[1]), "\t", 4)[0]
            }
        }
        return fmt.Errorf("break readline, we just want Name")
    })
    return pName, pUid
}

func getProcFd(pid int) (string, string) {
    fdInfo := map[string]string{}
    fdSocketInfo := map[string]string{}
    d, _ := filepath.Glob(fmt.Sprintf("/proc/%d/fd/[0-9]*", pid))
    for _, path := range d {
        fdLink, _ := os.Readlink(path)
        fdLinkSplit := strings.Split(fdLink, ":")

        pathSplit := strings.Split(path, "/")
        fd := pathSplit[len(pathSplit)-1]

        if fdLinkSplit[0] == "socket" {
            s := strings.Replace(fdLinkSplit[1], "[", "", -1)
            s = strings.Replace(s, "]", "", -1)
            fdSocketInfo[fd] = inode2Socket(s)
        }

        fdInfo[fd] = fdLink
    }

    fdData, _ := json.Marshal(fdInfo)
    fdSocketData, _ := json.Marshal(fdSocketInfo)

    return string(fdData), string(fdSocketData)
}

func getProcExe(pid int) string {
    return utils.ReadLink(fmt.Sprintf("/proc/%d/exe", pid))
}

func getProcEnv(pid int, env string) string {
    var envContent string
    envRegex := fmt.Sprintf(`\0%s=([^\s\0]+)`, env)
    match := utils.SearchString(fmt.Sprintf("/proc/%d/environ", pid), envRegex)
    if len(match) > 1 {
        envContent = match[1]
    }
    return envContent
}

func uid2Name(uid string) string {
    name := ""
    f, err := os.Open("/etc/passwd")
    if err != nil {
        return ""
    }
    defer f.Close()
    _ = utils.ReadLine(f, func(line string) error {
        info := strings.SplitN(line, ":", -1)
        if info[2] == uid {
            name = info[0]
        }
        return nil
    })
    return name

}

func gid2Group(gid string) string {
    group := ""
    f, err := os.Open("/etc/group")
    if err != nil {
        return ""
    }
    defer f.Close()
    _ = utils.ReadLine(f, func(line string) error {
        info := strings.SplitN(line, ":", -1)
        if info[2] == gid {
            group = info[0]
        }
        return nil
    })
    return group
}

func inode2Socket(inode string) string {
    socketInfo := ""
    for _, netType := range Net {
        f, err := os.Open(ProtoFile[netType])
        if err != nil {
            return "open file " + ProtoFile[netType] + " error"
        }
        defer f.Close()
        contentReg := regexp.MustCompile(`\S+`)
        if netType != "unix" {
            _ = utils.ReadLine(f, func(line string) error {
                line_array := contentReg.FindAllString(line, -1)
                if inode == line_array[9] {
                    ip_port := strings.Split(line_array[1], ":")
                    lip, lport := utils.ConvertIp(ip_port[0]), utils.Hex2Dec(ip_port[1])

                    fip_port := strings.Split(line_array[2], ":")
                    fip, fport := utils.ConvertIp(fip_port[0]), utils.Hex2Dec(fip_port[1])
                    socketInfo = fmt.Sprintf("[%s]%s:%d - %s:%d", netType, lip, lport, fip, fport)
                }
                return nil
            })
        } else {
            _ = utils.ReadLine(f, func(line string) error {
                line_array := contentReg.FindAllString(line, -1)
                if inode == line_array[6] {
                    if len(line_array) == 8 {
                        socketInfo = fmt.Sprintf("[%s]%s", netType, line_array[7])
                    } else {
                        socketInfo = fmt.Sprintf("[%s]path_is_null", netType)
                    }
                }
                return nil
            })

        }
        if socketInfo != "" {
            break
        }
    }
    return socketInfo
}

func main() {
    watcher, err := psnotify.NewWatcher()
    if err != nil {
        log.Fatal(err)
    }
    // Process events

    sig := make(chan os.Signal)
    // now, only care about Exec event
    go func() {
        for {
            select {
            case <-watcher.Fork:
                //	ppidinfo:= readProcess(ev.ParentPid)
                //	pidinfo:= readProcess(ev.ChildPid)
                //	log.Printf("[fork]: %+v\n ",pidinfo)
            case ev := <-watcher.Exec:
                pidinfo := readProcess(ev.Pid)
                if pidinfo != ""{
                    log.Printf("[exec]\n%+v\n", pidinfo)
                }else{
                    log.Printf("[exec]\ncan't not get pro %d info",ev.Pid)
                }
            case <-watcher.Exit:
                //	pidinfo := readProcess(ev.Pid)
                //	log.Printf("[exit]: %+v\n", pidinfo)
            case err := <-watcher.Error:
                log.Printf("error:", err)
            }
        }
    }()

    signal.Notify(sig, os.Interrupt, os.Kill, syscall.Signal(15))
    <-sig
    log.Println("done")
}
