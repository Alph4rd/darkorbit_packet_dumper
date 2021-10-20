
// Objects for json stringfy
var as3_ns = null;
var separator_string = null;
var my_json_object = null;
var fake_vtable = null;

var pep_base = null;

// String* stringifySpecializedToString(Atom value, ArrayObject* propertyWhitelist, FunctionObject* replacerFunction, String* gap);
var stringify_f     = null;

var packet_handler = null;
var packet_sender = null;

// Methods waiting for compilation before being hooked
var hook_queue = [];

var avm = {
    core : null,
    constant_pool : null,
    abc_env : null,
    top_level : null
};


Process.enumerateModules({
    onMatch: function(module) {
        if (module.name.indexOf("pepflash") >= 0) 
            pep_base = module;
    },
    onComplete: function() { }
});


// Used for parsing abc data
class CoolPtr {
    constructor(pointer) {
        this.ptr = pointer;
    }

    ReadU8() { 
        var r = this.ptr.readU8();
        this.ptr.add(1);
        return r;
    }

    ReadU32() {
        var data = new Uint8Array(this.ptr.readByteArray(5 * 4));
        var result = data[0];
        if (!(result & 0x00000080)) {
            this.ptr.add(1);
            return result;
        }
        result = (result & 0x0000007f) | data[1]<<7;
        if (!(result & 0x00004000)) {
            this.ptr.add(2);
            return result;
        }
        result = (result & 0x00003fff) | data[2]<<14;
        if (!(result & 0x00200000)) {
            this.ptr.add(2);
            return result;
        }
        result = (result & 0x001fffff) | data[3]<<21;
        if (!(result & 0x10000000)) {
            this.ptr.add(2);
            return result;
        }
        result = (result & 0x0fffffff) | data[4]<<28;
        this.ptr.add(5);
        return result;
    }
}

function findPattern(pattern, match_handler) {
    var ranges = Process.enumerateRangesSync({protection: 'r--', coalesce: true});
    var stop = false;

    for (var range of ranges) {
        Memory.scan(range.base, range.size, pattern, {
            onMatch: match_handler,
            onError: function(reason){ },
            onComplete: function() { }
        });
    }
}

function getMultiname(index) {
    var precomp_mn      = avm.constant_pool.add(0xe8).readPointer();
    var precomp_mn_size = avm.constant_pool.add(0x98).readU32();
    if (index < precomp_mn_size)
        return precomp_mn.add(0x18 + index * 0x18);
    return null;
}

function getObjectSize(object_ptr) {
    var gc_block_header = object_ptr.and((new NativePointer(4095)).not());
    return gc_block_header.add(0x4).readU32();
}

function removeKind(pointer) {
    return pointer.and(uint64(0x7).not());
}

function readAvmString(str_pointer, c=0) {
    str_pointer = removeKind(str_pointer); 
    if (str_pointer.equals(0))
        return "";
    
    var flags = str_pointer.add(0x24).readU32();
    var size  = str_pointer.add(0x20).readU32();

    var width = (flags & 0x1);
    size <<= width;

    if (size > 1024 || size < 0 || c > 1) 
        return "";
    
    // 
    if ((flags & (2 << 1)) != 0)
        return readAvmString(removeKind(str_pointer.add(0x18).readPointer()), c+1);

    var str_addr = str_pointer.add(0x10).readPointer();

    if (width)
        return str_addr.readUtf16String(size);
    return str_addr.readCString(size);
}

function getMethodName(method_info) {
    var name_list = avm.constant_pool.add(0x190).readPointer();
    var method_id = method_info.add(0x40).readU32();

    var name_index = name_list.add(4 + method_id * 4).readInt();

    if (name_index < 0) {
        name_index = -name_index;
        var multiname = getMultiname(name_index);
        if (multiname != 0) {
            console.log(multiname.add(0x8).readPointer());
            return readAvmString(multiname.readPointer());
        }

        return "";
    } else {
        // TODO: handle non negative names
    }
    return "";
}

function methodIsCompiled(method_info_ptr) {
    return ((method_info_ptr.add(0x60).readU32() >> 21) & 1) == 1;
}

function getPacketIdFromObj(packet_obj) {
    packet_obj = removeKind(packet_obj);
    var vtable = packet_obj.add(0x10).readPointer();

    // Hopefully the method index doesn't change
    var get_id_method_env = vtable.add(0x78 + 3 * 8).readPointer()
    if (get_id_method_env != 0) {
        var method_info = get_id_method_env.add(0x10).readPointer();
        var method_id   = method_info.add(0x40).readU32();
        var method_code = method_info.add(0x8).readPointer();

        var get_id_f = new NativeFunction(method_code, 'int64', ['pointer', 'uint64', 'pointer']);

        var get_id_args = Memory.alloc(0x10)
        get_id_args.writePointer(packet_obj);
        get_id_args.add(0x8).writeU64(0);

        return get_id_f(get_id_method_env, 1, get_id_args);
    }

    return null;
}

function getClassName(script_obj) {
    script_obj = removeKind(script_obj);
    var vtable = script_obj.add(0x10).readPointer();
    var traits = vtable.add(0x28).readPointer();
    var name_str = traits.add(0x90).readPointer();
    return readAvmString(name_str);
}

function packetToString(packet_obj) {
    if (stringify_f && my_json_object && separator_string)
        return readAvmString(stringify_f(my_json_object, packet_obj.add(1), 0, 0, separator_string ));

    return null;
}

// arg0 == method_env
// arg1 == avm arg_count
// arg2 == avm argv
function onPacketRecv(args) {
    var arg_count = args[1];
    var flash_args = ptr(args[2]);
    var packet_obj = removeKind(flash_args.add(8).readPointer());

    var packet_id = getPacketIdFromObj(packet_obj);
    var str_packet = packetToString(packet_obj);

    if (packet_id && str_packet)
        send({"type":0, "id":packet_id, "name":getClassName(packet_obj), "packet": JSON.parse(str_packet)});
};

function onPacketSend(args) {
    var arg_count = args[1];
    var flash_args = ptr(args[2]);
    var packet_obj = removeKind(flash_args.add(8).readPointer());

    var packet_id = getPacketIdFromObj(packet_obj);
    var str_packet = packetToString(packet_obj);

    if (packet_id && str_packet)
        send({"type":1, "id":packet_id, "name":getClassName(packet_obj), "packet": JSON.parse(str_packet)});
};

// TODO: support onLeave
function hookLater(method_ptr, callback) {
    hook_queue.push({method:method_ptr, handler:callback});
}

var previous_hooks = [];
Memory.scan(pep_base.base, pep_base.size, verifyjit_pattern, {
    onMatch : function(addr, size) {
        console.log("[+] Found verifyJit:", ptr(addr));

        Interceptor.attach(ptr(addr), {
            onEnter: function(args) { 
                this.method = ptr(args[1]);
                if (previous_hooks.length) {  
                    // On windows, the avm will crash if the permissions of the code page aren't
                    // RX, so in case the current code gets allocated in the same page as the code
                    // we hooked, we need to reset permissions.
                    previous_hooks.forEach(hk => {
                        var hk_page = hk.and(uint64(4096-1).not());
                        Memory.protect(hk_page, 4096, "r-x");
                    });
                }
            },
            onLeave: function(retval) {
                var hindex = hook_queue.findIndex(h => h.method.equals(this.method));
                if (hindex >= 0) {
                    var hook = hook_queue[hindex];
                    var code = this.method.add(0x8).readPointer();
                    previous_hooks.push(code);
                    Interceptor.attach(code, { onEnter: hook.handler });
                    hook_queue.splice(hindex, 1);
                }
            }
        });
    },
    onError: function(reason){ },
    onComplete: function() { }
});

Memory.scan(pep_base.base, pep_base.size, stringify_pattern, {
    onMatch : function(addr, size) {
        if (!stringify_f) {
            console.log("[+] Json stringify     :", ptr(addr));
            stringify_f = new NativeFunction(ptr(addr), 'pointer', ['pointer', 'pointer', 'uint64', 'uint64', 'pointer']);
        }
    },
    onError: function(reason){ },
    onComplete: function() { }
});

findPattern(darkbot_pattern, function(addr, size) {
    addr -= 228;
    if (as3_ns)
        return;
    var main_address    = ptr(addr + 0x540).readPointer();
    var vtable          = main_address.add(0x10).readPointer();
    var traits          = vtable.add(0x28).readPointer();
    avm.top_level       = vtable.add(0x8).readPointer();
    var vtable_init     = vtable.add(0x10).readPointer();
    var vtable_scope    = vtable_init.add(0x18).readPointer();
    avm.abc_env         = vtable_scope.add(0x10).readPointer();
    avm.core            = traits.add(0x8).readPointer();
    avm.constant_pool   = avm.abc_env.add(0x8).readPointer();

    var method_list      = avm.constant_pool.add(offsets.method_list).readPointer();
    var ns_list          = avm.core.add(offsets.ns_list).readPointer();
    var ns_count         = avm.core.add(0x80).readPointer();

    // ids are not reliable, might change after an update
    packet_handler = method_list.add(0x10 + packet_handler_id * 8).readPointer();
    packet_sender  = method_list.add(0x10 + packet_sender_id  * 8).readPointer();

    // Iterate namespaces
    for (var i = 0, c = 0; i < 0x40000 && c < ns_count; i++) {
        var namespace = ns_list.add(i * 8).readPointer();
        if (namespace == 0)
            continue;

        try { var namespace_str = namespace.add(0x18).readPointer(); }
        catch { break; }

        var s = readAvmString(namespace_str, 0);

        // Find as3 namespace
        if (s && s == "http://adobe.com/AS3/2006/builtin" && !as3_ns) {
            as3_ns = namespace;
            // Remove AtomKind bits
            var namespace_str = removeKind(namespace.add(0x18).readPointer());
            separator_string = Memory.dup(namespace_str, 0x28);
            separator_string.add(0x20).writeU64(0x0);

            my_json_object = Memory.alloc(0x38);
            my_json_object.add(0x30).writePointer(as3_ns);

            fake_vtable = Memory.alloc(0x38);
            fake_vtable.add(8).writePointer(avm.top_level);
            my_json_object.add(0x10).writePointer(fake_vtable);
            console.log("[+] Fake json object   :", my_json_object);
            break;
        }
        c++;
    }

    console.log("[+] Main address       :", main_address);
    console.log("[+] ConstPool address  :", avm.constant_pool);
    console.log("[+] AvmCore address    :", avm.core);
    console.log("[+] Namespace list     :", ns_list);
    console.log("[+] Packet handler     :", packet_handler.add(0x8));
    console.log("[+] Packet sender      :", packet_sender.add(0x8));


    // Hook methods, or wait for them to be jit compiled before hooking
    if (!methodIsCompiled(packet_handler)) {
        console.log("[+] Packet receiver is not compiled, waiting for it");
        hookLater(packet_handler, onPacketRecv);
    } else {
        Interceptor.attach(packet_handler.add(0x8).readPointer(), { onEnter: onPacketRecv });
    }

    if (!methodIsCompiled(packet_sender)) {
        console.log("[+] Packet sender is not compiled, waiting for it");
        hookLater(packet_sender, onPacketSend);
    } else {
        Interceptor.attach(packet_sender.add(0x8).readPointer(), { onEnter: onPacketSend });
    }
});
