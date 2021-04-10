@load base/frameworks/sumstats
event zeek_init()
    {
    local rall_res = SumStats::Reducer($stream="all_response", $apply=set(SumStats::SUM));
    local r404_res = SumStats::Reducer($stream="404_response", $apply=set(SumStats::SUM));
    local r404_uni = SumStats::Reducer($stream="404_uniqueresponse", $apply=set(SumStats::UNIQUE));
    
    SumStats::create([$name="404.requests.unique",
                      $epoch=10min,
                      $reducers=set(rall_res, r404_res, r404_uni),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        local r1 = result["all_response"];
                        local r2 = result["404_response"];
                        local r3 = result["404_uniqueresponse"];
                        if(r2$sum >= 2)
                        {
                        	if(r2$sum / r1$sum > 0.2)
                        	{
                        		if(r3$unique / r2$sum > 0.5)
                        		print fmt("%s is a scanner with %d scan attemps on %d urls", key$host, r2$sum, r3$unique);
                        	}
                        }
                        }]);
    }


event http_reply(c: connection, version: string, code: count, reason: string)
{
	SumStats::observe("all_response", [$host=c$id$orig_h], [$num=1]);
	if(code == 404)
	{
		SumStats::observe("404_response", [$host=c$id$orig_h], [$num=1]);
		SumStats::observe("404_uniqueresponse", [$host=c$id$orig_h], [$str=c$http$uri]);
	}
	
}

