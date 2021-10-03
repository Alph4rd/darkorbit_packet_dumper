
// Objects for json stringfy
var as3_ns = null;
var separator_string = null;
var my_json_object = null;
var fake_vtable = null;

var pep_base = null;

// String* stringifySpecializedToString(Atom value, ArrayObject* propertyWhitelist, FunctionObject* replacerFunction, String* gap);
var stringify_f     = null;


Process.enumerateModules({
    onMatch: function(module) {
        if (module.name.indexOf("pepflash") >= 0) 
            pep_base = module;
    },
    onComplete: function() { }
});

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

function readAvmString(address, c) {
    var flags = Memory.readU32(ptr( address + 0x24 ));
    var size = Memory.readU32(ptr( address + 0x20 ));

    var width = (flags & 0x1);
    size <<= width;

    if (size > 1024 || size < 0 || c > 1) 
        return null;

    var str_addr = Memory.readU64(ptr( address + 0x10 ));
    if (str_addr == 0)
        return read_string(Memory.readU64(ptr( address + 0x18 )));

    if (width)
        return ptr(str_addr).readUtf16String(size);
    return ptr(str_addr).readCString(size);
}

function getPacketIdFromObj(packet_obj) {
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
    var vtable = script_obj.add(0x10).readPointer();
    var traits = vtable.add(0x28).readPointer();
    var name_str = traits.add(0x90).readU64();
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
    var packet_obj = flash_args.add(8).readPointer();

    var packet_id = getPacketIdFromObj(packet_obj);
    var str_packet = packetToString(packet_obj);

    if (packet_id && str_packet)
        send({"type":0, "id":packet_id, "name":getClassName(packet_obj), "packet": JSON.parse(str_packet)});
};

function onPacketSend(args) {
    var arg_count = args[1];
    var flash_args = ptr(args[2]);
    var packet_obj = flash_args.add(8).readPointer();

    var packet_id = getPacketIdFromObj(packet_obj);
    var str_packet = packetToString(packet_obj);

    if (packet_id && str_packet)
        send({"type":1, "id":packet_id, "name":getClassName(packet_obj), "packet": JSON.parse(str_packet)});
};

findPattern(darkbot_pattern, function(addr, size) {
    console.log("[+] Darkbot found!!");

    addr -= 228;
    var main_address    = ptr(addr + 0x540).readPointer();
    var vtable          = main_address.add(0x10).readPointer();
    var traits          = vtable.add(0x28).readPointer();
    var top_level       = vtable.add(0x8).readPointer();
    var vtable_init     = vtable.add(0x10).readPointer();
    var vtable_scope    = vtable_init.add(0x18).readPointer();
    var abc_env         = vtable_scope.add(0x10).readPointer();
    var avm_core        = traits.add(0x8).readPointer();
    var pool            = abc_env.add(0x8).readPointer();

    var method_list      = pool.add(offsets.method_list).readPointer();
    var ns_list          = avm_core.add(offsets.ns_list).readPointer();


    console.log('[+] Darkbot pattern found at: ' + addr.toString(16));
    console.log('[+] Main address: ' + main_address);
    console.log('[+] ConstPool address: ' + pool);
    console.log('[+] AvmCore address: ' + avm_core);
    console.log("[!] Namespace list: ", ns_list);

    var packet_handler = method_list.add(0x10 + packet_handler_id * 8).readPointer();
    var packet_sender  = method_list.add(0x10 + packet_sender_id  * 8).readPointer();

    console.log('[+] Packet handler : ' + packet_handler);
    console.log('[+] Packet sender  : ' + packet_sender);

    // I believe these could be null if not JITd yed
    var handler_code = packet_handler.add(0x8).readPointer();
    var sender_code  = packet_sender.add(0x8).readPointer();

    Interceptor.attach(handler_code, {
        onEnter: onPacketRecv
    });

    Interceptor.attach(sender_code, {
        onEnter: onPacketSend
    });

    // hashtable, the vm seems to use gc to find out when to stop iterating
    for (var i = 0; i < 29000; i++) {
        var namespace = ns_list.add(i * 8).readPointer();
        if (namespace == 0)
            continue;

        try { var namespace_str = namespace.add(0x18).readU64(); }
        catch { break; }

        var s = readAvmString(namespace_str, 0);

        // Find as3 namespace
        if (s && s == "http://adobe.com/AS3/2006/builtin" && !as3_ns) {
            as3_ns = namespace;
            separator_string = Memory.dup(namespace, 0x28);
            separator_string.add(0x20).writeU64(0x0);

            my_json_object = Memory.alloc(0x38);
            my_json_object.add(0x30).writePointer(as3_ns);

            fake_vtable = Memory.alloc(0x38);
            fake_vtable.add(8).writePointer(top_level);
            my_json_object.add(0x10).writePointer(fake_vtable);
            console.log("[+] Fake json object at: ", my_json_object);
        }
    }
});

findPattern(stringify_pattern, function(addr, size) {
    if (addr > pep_base.base && addr < (pep_base + pep_base.size)) {
        console.log("[+] Json stringify:", addr.toString(16));
        stringify_f = new NativeFunction(ptr(addr), 'uint64', ['pointer', 'pointer', 'uint64', 'uint64', 'pointer']);
    }
});
