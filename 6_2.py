 @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)
    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.logger.info('datapath         '
                        'in-port  eth-dst           '
                         'out-port packets  bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            self.logger.info('%016x %8x %17s %8x %8d %8d',
                             ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        endtime = time.time()        timeinterval = int(endtime - self.starttime)        body = ev.msg.body
        datapath = ev.msg.datapath
        self.logger.info('datapath         port     '                         'rx-pkts  rx-bytes rx-error '                         'tx-pkts  tx-bytes tx-error')        self.logger.info('---------------- -------- '                         '-------- -------- -------- '                         '-------- -------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',                            ev.msg.datapath.id, stat.port_no,
                            stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                            stat.tx_packets, stat.tx_bytes, stat.tx_errors)            #link 1 s3 to s1
            if datapath.id == 3 and stat.port_no == 2:
                f1 = open('link1.txt', 'ab')
                self.l1_prev = self.l1_curr                self.l1_curr = stat.rx_bytes + stat.tx_bytes                self.v1 = (self.l1_curr - self.l1_prev) / (1024) / 10                f1.write('At time %d, link 1 bps:%.0f \n' % (timeinterval, self.v1))
                f1.close()            #link 2: s3 to s2            if datapath.id == 3 and stat.port_no == 3:                f2 = open('link2.txt', 'ab')                self.l2_prev = self.l2_curr                self.l2_curr = stat.rx_bytes + stat.tx_bytes                self.v2 = (self.l2_curr - self.l2_prev) / (1024) / 10                f2.write('At time %d, link 2 bps:%.0f \n' % (timeinterval, self.v2))                f2.close()            #link3: s4 to s1
            if datapath.id == 4 and stat.port_no == 2:                f3 = open('link3.txt', 'ab')                self.l3_prev = self.l3_curr                self.l3_curr = stat.rx_bytes + stat.tx_bytes                self.v3 = (self.l3_curr - self.l3_prev) / (1024) / 10                f3.write('At time %d, link 3 bps:%.0f \n' % (timeinterval, self.v3))                f3.close()            #link4: s4 to s2            if datapath.id == 4 and stat.port_no == 3:                f4 = open('link4.txt', 'ab')                self.l4_prev = self.l4_curr                self.l4_curr = stat.rx_bytes + stat.tx_bytes                self.v4 = (self.l4_curr - self.l4_prev) / (1024) / 10                f4.write('At time %d, link 4 bps:%.0f \n' % (timeinterval, self.v4))                f4.close()            #link5: s5 to s1
            if datapath.id == 5 and stat.port_no == 2:
                f5 = open('link5.txt', 'ab')                self.l5_prev = self.l5_curr                self.l5_curr = stat.rx_bytes + stat.tx_bytes                self.v5 = (self.l5_curr - self.l5_prev) / (1024) / 10                f5.write('At time %d, link 5 bps:%.0f \n' % (timeinterval, self.v5))                f5.close()            #link6: s5 to s2            if datapath.id == 5 and stat.port_no == 3:                f6 = open('link6.txt', 'ab')                self.l6_prev = self.l6_curr                self.l6_curr = stat.rx_bytes + stat.tx_bytes                self.v6 = (self.l6_curr - self.l6_prev) / (1024) / 10                f6.write('At time %d, link 6 bps:%.0f \n' % (timeinterval, self.v6))                f6.close()