// 泽西破解 - 卡密验证绕过 Frida Hook
// 用法: frida -U -f <package_name> -l kami_hook.js

var libName = "target_cracked.so";

function hookKamiVerify() {
    var base = Module.findBaseAddress(libName);
    if (!base) {
        console.log("[!] " + libName + " 未加载，等待...");
        return false;
    }
    console.log("[+] 泽西破解 Hook 已启动");
    console.log("[+] Base: " + base);

    // Hook 1: strcmp 劫持 (check值比对永远成功)
    Interceptor.attach(base.add(0xD0E0), {
        onEnter: function(args) {
            this.s1 = Memory.readUtf8String(args[0]);
            this.s2 = Memory.readUtf8String(args[1]);
        },
        onLeave: function(retval) {
            if (this.s1 && this.s2 && this.s1.length === 32 && this.s2.length === 32) {
                console.log("[strcmp] local_check: " + this.s1);
                console.log("[strcmp] server_check: " + this.s2);
                retval.replace(0);
                console.log("[strcmp] -> 强制返回0 (匹配)");
            }
        }
    });

    // Hook 2: 内存Patch - mov w27, #1 (验证永远成功)
    var patchAddr = base.add(0x118B4);
    Memory.patchCode(patchAddr, 4, function(code) {
        var writer = new Arm64Writer(code, { pc: patchAddr });
        writer.putInstruction(0x52800037); // mov w27, #1
        writer.flush();
    });
    console.log("[patch] 0x118B4: cset w27,eq -> mov w27,#1");

    // Hook 3: NOP失败分支
    var nopAddr = base.add(0x118C4);
    Memory.patchCode(nopAddr, 4, function(code) {
        var writer = new Arm64Writer(code, { pc: nopAddr });
        writer.putNop();
        writer.flush();
    });
    console.log("[patch] 0x118C4: cbz -> nop");

    // Hook 4: NOP code检查
    var codeCheckAddr = base.add(0x1152C);
    Memory.patchCode(codeCheckAddr, 4, function(code) {
        var writer = new Arm64Writer(code, { pc: codeCheckAddr });
        writer.putNop();
        writer.flush();
    });
    console.log("[patch] 0x1152C: b.ne -> nop");

    // Hook 5: 监控HTTP请求
    Interceptor.attach(base.add(0xD6E4), {
        onEnter: function(args) {
            console.log("[http] Host: " + Memory.readUtf8String(args[0]));
            console.log("[http] Path: " + Memory.readUtf8String(args[1]));
            if (args[2] && !args[2].isNull()) {
                console.log("[http] Body: " + Memory.readUtf8String(args[2]));
            }
        }
    });

    // Hook 6: 监控JSON解析
    Interceptor.attach(base.add(0xF3C4), {
        onEnter: function(args) {
            this.key = Memory.readUtf8String(args[1]);
        },
        onLeave: function(retval) {
            if (this.key) {
                console.log("[json] key=" + this.key + " -> " + retval);
            }
        }
    });

    console.log("[+] 泽西破解 - 所有Hook已安装完成");
    return true;
}

// 尝试立即Hook，失败则等待库加载
if (!hookKamiVerify()) {
    var checkInterval = setInterval(function() {
        if (hookKamiVerify()) {
            clearInterval(checkInterval);
        }
    }, 500);
}
