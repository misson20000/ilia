print("Loading HIPC dissector")

hipc = Proto("ilia", "Horizon IPC (Nintendo Switch) (ilia)")

local pf_rq_type = ProtoField.uint16("ilia.rq.type", "Message Type", base.DEC, nil)
local pf_rq_num_xd = ProtoField.uint32("ilia.rq.num_xd", "Number of X Descriptors", base.DEC, nil, 0x000f0000)
local pf_rq_num_ad = ProtoField.uint32("ilia.rq.num_ad", "Number of A Descriptors", base.DEC, nil, 0x00f00000)
local pf_rq_num_bd = ProtoField.uint32("ilia.rq.num_bd", "Number of B Descriptors", base.DEC, nil, 0x0f000000)
local pf_rq_num_wd = ProtoField.uint32("ilia.rq.num_wd", "Number of W Descriptors", base.DEC, nil, 0xf0000000)
local pf_rq_rd_words = ProtoField.uint32("ilia.rq.rd_words", "Raw Data Size (in words)", base.HEX, nil, 0x0000003f)
local pf_rq_cd_flags = ProtoField.uint32("ilia.rq.cd_flags", "C Descriptor Flags", base.DEC, nil, 0x00003c00)
local pf_rq_has_hd = ProtoField.bool("ilia.rq.has_hd", "Has Handle Descriptor", 32, {"yes", "no"}, 0x80000000)
local pf_rq_dom_cmd = ProtoField.uint8("ilia.rq.domain.command", "Domain Command")
local pf_rq_dom_in_obj_count = ProtoField.uint8("ilia.rq.domain.in_obj_count", "Domain Input Object Count")
local pf_rq_dom_payload_len = ProtoField.uint16("ilia.rq.domain.payload_len", "Domain Payload Length")
local pf_rq_dom_id = ProtoField.uint32("ilia.rq.domain.id", "Domain Object ID")
local pf_rq_dom_in_objs = ProtoField.bytes("ilia.rq.domain.in_objs", "Domain Input Object IDs")
local pf_rq_magic = ProtoField.string("ilia.rq.magic", "Request Magic")
local pf_rq_id = ProtoField.uint32("ilia.rq.id", "Request ID", base.DEC)
local pf_rq_raw_params = ProtoField.bytes("ilia.rq.raw_params", "Raw Data")

local pf_rs_type = ProtoField.uint16("ilia.rs.type", "Message Type", base.DEC, nil)
local pf_rs_num_xd = ProtoField.uint32("ilia.rs.num_xd", "Number of X Descriptors", base.DEC, nil, 0x000f0000)
local pf_rs_num_ad = ProtoField.uint32("ilia.rs.num_ad", "Number of A Descriptors", base.DEC, nil, 0x00f00000)
local pf_rs_num_bd = ProtoField.uint32("ilia.rs.num_bd", "Number of B Descriptors", base.DEC, nil, 0x0f000000)
local pf_rs_num_wd = ProtoField.uint32("ilia.rs.num_wd", "Number of W Descriptors", base.DEC, nil, 0xf0000000)
local pf_rs_rd_words = ProtoField.uint32("ilia.rs.rd_words", "Raw Data Size (in words)", base.HEX, nil, 0x0000003f)
local pf_rs_cd_flags = ProtoField.uint32("ilia.rs.cd_flags", "C Descriptor Flags", base.DEC, nil, 0x00003c00)
local pf_rs_has_hd = ProtoField.bool("ilia.rs.has_hd", "Has Handle Descriptor", 32, {"yes", "no"}, 0x80000000)
local pf_rs_dom_out_obj_count = ProtoField.uint8("ilia.rs.domain.out_obj_count", "Domain Output Object Count")
local pf_rs_magic = ProtoField.string("ilia.rs.magic", "Response Magic")
local pf_rs_code = ProtoField.uint32("ilia.rs.id", "Response Code", base.DEC)
local pf_rs_raw_params = ProtoField.bytes("ilia.rs.raw_params", "Raw Data")

local pf_xd_size = ProtoField.uint32("ilia.xd.size", "Size", base.HEX, nil, 0xFFFF0000)
local pf_ad_lsize = ProtoField.uint32("ilia.ad.lsize", "Size (low bits)", base.HEX, nil, 0xFFFFFFFF)
local pf_ad_hsize = ProtoField.uint32("ilia.ad.hsize", "Size (high bits)", base.HEX, nil, 0x0F000000)
local pf_bd_lsize = ProtoField.uint32("ilia.bd.lsize", "Size (low bits)", base.HEX, nil, 0xFFFFFFFF)
local pf_bd_hsize = ProtoField.uint32("ilia.bd.hsize", "Size (high bits)", base.HEX, nil, 0x0F000000)
local pf_cd_laddr = ProtoField.uint32("ilia.cd.laddr", "Address (low bits)", base.HEX, nil, 0xFFFFFFFF)
local pf_cd_haddr = ProtoField.uint32("ilia.cd.haddr", "Address (high bits)", base.HEX, nil, 0xFFFF0000)
local pf_cd_size = ProtoField.uint32("ilia.cd.size", "Size", base.HEX, nil, 0x0000FFFF)

local pf_descriptor_data = ProtoField.bytes("ilia.descriptor.data", "Data")

hipc.fields = {
   pf_rq_type,
   pf_rq_num_xd,
   pf_rq_num_ad,
   pf_rq_num_bd,
   pf_rq_num_wd,
   pf_rq_rd_words,
   pf_rq_cd_flags,
   pf_rq_has_hd,
   pf_rq_dom_cmd,
   pf_rq_dom_in_obj_count,
   pf_rq_dom_payload_len,
   pf_rq_dom_id,
   pf_rq_dom_in_objs,
   pf_rq_magic,
   pf_rq_id,
   pf_rq_raw_params,

   pf_rs_type,
   pf_rs_num_xd,
   pf_rs_num_ad,
   pf_rs_num_bd,
   pf_rs_num_wd,
   pf_rs_rd_words,
   pf_rs_cd_flags,
   pf_rs_has_hd,
   pf_rs_dom_out_obj_count,
   pf_rs_magic,
   pf_rs_code,
   pf_rs_raw_params,

   pf_xd_size,
   pf_ad_lsize,
   pf_ad_hsize,
   pf_bd_lsize,
   pf_bd_hsize,
   pf_cd_laddr,
   pf_cd_haddr,
   pf_cd_size,   
   pf_descriptor_data }

local f_rq_xds = Field.new("ilia.rq.num_xd")
local f_rq_ads = Field.new("ilia.rq.num_ad")
local f_rq_bds = Field.new("ilia.rq.num_bd")
local f_rq_wds = Field.new("ilia.rq.num_wd")
local f_rq_rd_words = Field.new("ilia.rq.rd_words")
local f_rq_cd_flags = Field.new("ilia.rq.cd_flags")
local f_rq_has_hd = Field.new("ilia.rq.has_hd")
local f_rq_dom_in_obj_count = Field.new("ilia.rq.domain.in_obj_count")
local f_rq_dom_payload_len = Field.new("ilia.rq.domain.payload_len")

local f_rs_xds = Field.new("ilia.rs.num_xd")
local f_rs_ads = Field.new("ilia.rs.num_ad")
local f_rs_bds = Field.new("ilia.rs.num_bd")
local f_rs_wds = Field.new("ilia.rs.num_wd")
local f_rs_rd_words = Field.new("ilia.rs.rd_words")
local f_rs_cd_flags = Field.new("ilia.rs.cd_flags")
local f_rs_has_hd = Field.new("ilia.rs.has_hd")

local f_xd_size = Field.new("ilia.xd.size")
local f_ad_lsize = Field.new("ilia.ad.lsize")
local f_ad_hsize = Field.new("ilia.ad.hsize")
local f_bd_lsize = Field.new("ilia.bd.lsize")
local f_bd_hsize = Field.new("ilia.bd.hsize")
local f_cd_size = Field.new("ilia.cd.size")

local f_interface_name = Field.new("frame.interface_name")

function hipc.dissector(buffer, pinfo, tree)
   pinfo.cols.protocol:set("HIPC")
   local request_tree = tree:add(hipc, buffer(0, 0x100), "HIPC Request")
   request_tree:add_le(pf_rq_type, buffer(0, 2))
   request_tree:add_le(pf_rq_num_xd, buffer(0, 4))
   request_tree:add_le(pf_rq_num_ad, buffer(0, 4))
   request_tree:add_le(pf_rq_num_bd, buffer(0, 4))
   request_tree:add_le(pf_rq_num_wd, buffer(0, 4))

   request_tree:add_le(pf_rq_rd_words, buffer(4, 4))
   request_tree:add_le(pf_rq_cd_flags, buffer(4, 4))
   request_tree:add_le(pf_rq_has_hd, buffer(4, 4))
   
   local head = 8

   if f_rq_has_hd()() then
      local hdbegin = head
      local hd = buffer(head, 4):le_uint()
      head = head + 4
      local sendPid = bit32.band(hd, 1) == 1
      local pid = 0
      if sendPid then
         pid = buffer(head, 8):le_uint64()
         head = head + 8
      end
      local numCopyHandles = bit32.band(bit32.rshift(hd, 1), 15)
      local numMoveHandles = bit32.band(bit32.rshift(hd, 5), 15)
      local copyHandles = {}
      local moveHandles = {}
      for i=1,numCopyHandles do
         copyHandles[i] = buffer(head, 4)
         head = head + 4
      end
      for i=1,numMoveHandles do
         moveHandles[i] = buffer(head, 4)
         head = head + 4
      end
   end

   local data_head = 0x100

   local inst_f_xds = f_rq_xds()
   if inst_f_xds() > 0 then
      local xd_tree = request_tree:add("X Descriptors")
      for i=1, f_rq_xds()() do
	 local this_xd = xd_tree:add("X Descriptor #" .. i)
	 this_xd:add_le(pf_xd_size, buffer(head, 4))
	 sz = f_xd_size()()
	 this_xd:add(pf_descriptor_data, buffer(data_head, sz))
	 data_head = data_head + sz
	 head = head + 8
      end
   end

   local inst_f_ads = f_rq_ads()
   if inst_f_ads() > 0 then
      local ad_tree = request_tree:add("A Descriptors")
      for i=1, f_rq_ads()() do
	 local this_ad = ad_tree:add("A Descriptor #" .. i)
	 this_ad:add_le(pf_ad_lsize, buffer(head, 4))
	 this_ad:add_le(pf_ad_hsize, buffer(head + 8, 4))
	 sz = f_ad_lsize()()
	 this_ad:add(pf_descriptor_data, buffer(data_head, sz))
	 data_head = data_head + sz
	 head = head + 12
      end
   end

   local inst_f_bds = f_rq_bds()
   if inst_f_bds() > 0 then
      local bd_tree = request_tree:add("B Descriptors")
      for i=1, f_rq_bds()() do
	 local this_bd = bd_tree:add("B Descriptor #" .. i)
	 this_bd:add_le(pf_bd_lsize, buffer(head, 4))
	 this_bd:add_le(pf_bd_hsize, buffer(head + 8, 4))
	 sz = f_bd_lsize()()
	 this_bd:add(pf_descriptor_data, buffer(data_head, sz))
	 data_head = data_head + sz
	 head = head + 12
      end
   end

   local inst_f_wds = f_rq_wds()
   head = head + (12 * inst_f_wds())
   local rd_start = head
   
   local cd_flags = f_rq_cd_flags()()
   local num_cds = 0
   if cd_flags == 2 then
      num_cds = 1
   end
   if cd_flags >= 2 then
      num_cds = cd_flags - 2
   end
   if num_cds > 0 then
      local cd_tree = request_tree:add("C Descriptors")
      local cd_head = head + (f_rq_rd_words()() * 4)
      for i=1, num_cds do
	 local this_cd = cd_tree:add("C Descriptor #" .. i)
	 this_cd:add_le(pf_cd_laddr, buffer(cd_head, 4))
	 this_cd:add_le(pf_cd_haddr, buffer(cd_head+4, 4))
	 this_cd:add_le(pf_cd_size, buffer(cd_head+4, 4))
	 sz = f_cd_size()()
	 this_cd:add(pf_descriptor_data, buffer(data_head, sz))
	 data_head = data_head + sz
	 cd_head = cd_head + 8
      end
   end
   
   head = bit32.band(head + 15, 0xFFFFFFF0) -- align head for aligned data section

   local inst_f_rd_words = f_rq_rd_words()
   local magic = buffer(head, 4):le_uint()
   if magic == 0x49434653 then
      request_tree:add_le(pf_rq_magic, buffer(head, 4))
      request_tree:add_le(pf_rq_id, buffer(head + 8, 4))
      request_tree:add_le(pf_rq_raw_params, buffer(head + 16, (inst_f_rd_words() * 4) - 16)) -- won't handle c descriptor 16 lists properly but eeh I don't care
   else
      request_tree:add_le(pf_rq_dom_cmd, buffer(head, 1))
      request_tree:add_le(pf_rq_dom_in_obj_count, buffer(head+1, 1))
      request_tree:add_le(pf_rq_dom_payload_len, buffer(head+2, 2))
      request_tree:add_le(pf_rq_dom_id, buffer(head+4, 4))
      request_tree:add_le(pf_rq_magic, buffer(head+16, 4))
      request_tree:add_le(pf_rq_id, buffer(head+24, 4))
      local payload_len = f_rq_dom_payload_len()()
      request_tree:add_le(pf_rq_raw_params, buffer(head+32, payload_len - 16))
      request_tree:add_le(pf_rq_dom_in_objs, buffer(head+16+payload_len, f_rq_dom_in_obj_count()()*4))
   end

   head = data_head

   local response_tree = tree:add(hipc, buffer(head, 0x100), "HIPC Response")
   local rs_buffer = buffer(head, 0x100)
   response_tree:add_le(pf_rs_type, rs_buffer(0, 2))
   response_tree:add_le(pf_rs_num_xd, rs_buffer(0, 4))
   response_tree:add_le(pf_rs_num_ad, rs_buffer(0, 4))
   response_tree:add_le(pf_rs_num_bd, rs_buffer(0, 4))
   response_tree:add_le(pf_rs_num_wd, rs_buffer(0, 4))

   response_tree:add_le(pf_rs_rd_words, rs_buffer(4, 4))
   response_tree:add_le(pf_rs_cd_flags, rs_buffer(4, 4))
   response_tree:add_le(pf_rs_has_hd, rs_buffer(4, 4))

   local head = head + 8
   head = head + (f_rs_xds()() * 8)
   head = head + (f_rs_ads()() * 12)
   head = head + (f_rs_bds()() * 12)
   head = head + (f_rs_wds()() * 12)
   
   head = data_head + bit32.band(head - data_head + 15, 0xFFFFFFF0) -- align head for aligned data section
   magic = buffer(head, 4):le_uint()
   if magic == 0x4f434653 then
      response_tree:add_le(pf_rs_magic, buffer(head, 4))
      response_tree:add_le(pf_rs_code, buffer(head + 8, 4))
      response_tree:add_le(pf_rs_raw_params, buffer(head + 16, (f_rs_rd_words()() * 4) - 16))
   else
      response_tree:add_le(pf_rs_dom_out_obj_count, buffer(head, 4))
      response_tree:add_le(pf_rs_magic, buffer(head + 16, 4))
      response_tree:add_le(pf_rs_code, buffer(head + 24, 4))
      response_tree:add_le(pf_rs_raw_params, buffer(head + 32, (f_rs_rd_words()() * 4) - 16))
   end
end
