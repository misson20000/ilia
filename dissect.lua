print("Loading CMIF dissector")

cmif = Proto("ilia-cmif", "Command Message Interface (Nintendo Switch) (ilia-cmif)")

local pf_rq_magic = ProtoField.string("ilia-cmif.rq.magic", "Request Magic")
local pf_rq_id = ProtoField.uint32("ilia-cmif.rq.id", "Request ID", base.DEC)
local pf_rq_raw_params = ProtoField.bytes("ilia-cmif.rq.raw_params", "Raw Data")

local pf_result = ProtoField.uint32("ilia-cmif.result", "Result Code", base.HEX)
local pf_meta = ProtoField.bytes("ilia-cmif.meta_info", "Message Meta Info")
local pf_buffer = ProtoField.bytes("ilia-cmif.buffer", "Buffer")
local pf_buffer_type = ProtoField.uint32("ilia-cmif.buffer_type", "Buffer Type", base.HEX)

local pf_rs_magic = ProtoField.string("ilia-cmif.rs.magic", "Response Magic")
local pf_rs_code = ProtoField.uint32("ilia-cmif.rs.id", "Response Code", base.HEX)
local pf_rs_raw_params = ProtoField.bytes("ilia-cmif.rs.raw_params", "Raw Data")

cmif.fields = {
   pf_rq_magic,
   pf_rq_id,
   pf_rq_raw_params,

   pf_result,
   pf_meta,
   pf_buffer,
   pf_buffer_type,
   
   pf_rs_magic,
   pf_rs_code,
   pf_rs_raw_params
}

local f_result = Field.new("ilia-cmif.result")

local f_interface_name = Field.new("frame.interface_name")

function cmif.dissector(buffer, pinfo, tree)
   pinfo.cols.protocol:set("CMIF")
   local transaction_tree = tree:add(cmif, buffer, "CMIF Transaction")
   local segments = {}
   local segment_names = {
      [0] = "RequestPas",
      [1] = "RequestData",
      [2] = "MetaInfo",
      [3] = "ResponsePas",
      [4] = "ResponseData",
      [5] = "ResultCode",
      [6] = "Buffers"
   }
   local position = 0
   while position < buffer:len() do
      local chunk_type = buffer(position, 1):le_uint()
      local chunk_size = buffer(position + 1, 4):le_uint()
      local chunk_data = buffer(position + 9, chunk_size)

      local name = segment_names[chunk_type]
      if name ~= nil then
         segments[name] = chunk_data
      else
         print("WARNING: unknown segment type " .. chunk_type)
      end
      
      position = position + 9 + chunk_size
   end

   if segments.ResultCode ~= nil then
      local t_result = transaction_tree:add_le(pf_result, segments.ResultCode)
      if f_result()() ~= 0 then
         t_result:add_expert_info(PI_RESPONSE_CODE, PI_WARN, "ProcessCommand returned an error")
      end
   else
      transaction_tree:add_expert_info(PI_UNDECODED, PI_NOTE, "Missing ResultCode (did ProcessCommand return?)")
   end

   if segments.MetaInfo == nil then
      transaction_tree:add_expert_info(PI_UNDECODED, PI_ERROR, "Missing MetaInfo")
      return
   end
   
   transaction_tree:add(pf_meta, segments.MetaInfo)

   local bytes_in = segments.MetaInfo(0x8, 4):le_uint()
   local bytes_out = segments.MetaInfo(0x10, 4):le_uint()
   local buffer_count = segments.MetaInfo(0x18, 4):le_uint()
   local in_interface_count = segments.MetaInfo(0x1c, 4):le_uint()
   local out_interface_count = segments.MetaInfo(0x20, 4):le_uint()
   local in_handles_count = segments.MetaInfo(0x24, 4):le_uint()
   local out_handles_count = segments.MetaInfo(0x28, 4):le_uint()
   
   if segments.RequestData ~= nil then
      local rq_buffer = segments.RequestData(0, bytes_in)
      transaction_tree:add_le(pf_rq_magic, rq_buffer(0x0, 4))
      transaction_tree:add_le(pf_rq_id, rq_buffer(0x8, 4))
      if bytes_in > 0x10 then
         transaction_tree:add_le(pf_rq_raw_params, rq_buffer(0x10, bytes_in-0x10))
      end
   end

   if segments.ResponseData ~= nil then
      local rs_buffer = segments.ResponseData(0, bytes_out)
      transaction_tree:add_le(pf_rs_magic, rs_buffer(0x0, 4))
      transaction_tree:add_le(pf_rs_code, rs_buffer(0x8, 4))
      if bytes_out > 0x10 then
         transaction_tree:add_le(pf_rs_raw_params, rs_buffer(0x10, bytes_out-0x10))
      end
   end

   if segments.Buffers ~= nil then
      local index = 0
      local position = 0
      local b = segments.Buffers
      while position < b:len() do
         local buffer_size = b(position, 4):le_uint()
         local buffer_tree = transaction_tree:add(pf_buffer, b(position + 8, buffer_size))
         buffer_tree:add_le(pf_buffer_type, segments.MetaInfo(0x2c + (index * 4), 4))
         position = position + 8 + buffer_size
         index = index + 1
      end
   end
end

