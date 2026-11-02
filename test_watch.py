import asyncio
import signal
import time
import unittest
from unittest.mock import AsyncMock, patch
from urllib.parse import urlsplit
import watch


def result(site, ok=True, **kw):
    kw.setdefault('outcome', 'expected_exit' if ok else 'probe_failed')
    address = watch.EXPECTED if ok else ('198.51.100.7' if kw['outcome']=='exit_mismatch' else None)
    return dict(site=site, ok=ok, ip=address, **kw)


class StateTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.
        self.state = watch.State(lambda: self.now)

    def apply(self, results, seq=1, epoch=None, started=None, phase='regular'):
        return self.state.result(self.state.epoch if epoch is None else epoch, seq,
                                 self.now if started is None else started, results, 'default_route',phase)

    def test_startup_does_not_close(self):
        self.assertFalse(self.state.should_close())
        self.assertFalse(self.state.status()['exit_confirmed'])

    def test_both_healthy(self):
        self.apply([result('a'), result('b')])
        self.assertFalse(self.state.should_close())
        self.assertTrue(self.state.status()['exit_confirmed'])

    def test_one_failure_never_closes_in_either_order(self):
        for items in [[result('a',False),result('b')],[result('a'),result('b',False)]]:
            self.apply(items, seq=self.state.last_seq+1)
            self.assertFalse(self.state.should_close())
            self.assertEqual(self.state.reason,'one_site_ok')

    def test_one_mismatch_and_one_good_closes(self):
        self.apply([result('a',False, outcome='exit_mismatch'),result('b')])
        self.assertTrue(self.state.should_close())
        self.assertEqual(self.state.close_reason(),'exit_mismatch')

    def test_both_failed_waits_for_recheck(self):
        self.apply([result('a',False),result('b',False)])
        self.assertFalse(self.state.should_close())
        self.assertEqual(self.state.reason,'awaiting_three_site_recheck')

    def test_two_mismatches_close(self):
        self.apply([result('a',False,outcome='exit_mismatch'),result('b',False,outcome='exit_mismatch')])
        self.assertTrue(self.state.should_close())

    def test_mismatch_plus_timeout_close(self):
        self.apply([result('a',False,outcome='exit_mismatch'),result('b',False,error='timeout')])
        self.assertTrue(self.state.should_close())

    def test_one_recovered_site_clears_uncertainty(self):
        self.apply([result('a',False),result('b',False)])
        self.apply([result('c'),result('d',False)],seq=2)
        self.assertFalse(self.state.should_close())

    def test_expired_success_does_not_close(self):
        self.apply([result('a'),result('b')])
        self.now += watch.FRESH_FOR+1
        self.assertFalse(self.state.should_close())
        self.assertFalse(self.state.status()['exit_confirmed'])

    def test_stale_bad_round_cannot_close(self):
        self.assertFalse(self.apply([result('a',False),result('b',False)],started=self.now-watch.FRESH_FOR))
        self.assertFalse(self.state.should_close())

    def test_late_old_failure_does_not_override_new_success(self):
        self.apply([result('a'),result('b')],seq=3)
        self.assertFalse(self.apply([result('c',False),result('d',False)],seq=2))
        self.assertFalse(self.state.should_close())

    def test_network_change_does_not_itself_close(self):
        old_epoch=self.state.epoch
        self.state.invalidate('network_changed')
        self.assertFalse(self.state.should_close())
        self.assertFalse(self.apply([result('a',False),result('b',False)],epoch=old_epoch))

    def test_other_path_success_cannot_erase_failed_recheck(self):
        self.apply([result(str(i),False) for i in range(5)],seq=1,phase='extended')
        self.state.result(0,2,self.now,[result('c'),result('d')],'nextin_proxy')
        self.assertTrue(self.state.should_close())

    def test_old_failure_on_different_path_still_counts(self):
        self.state.result(0,2,self.now,[result('c'),result('d')],'nextin_proxy')
        self.assertTrue(self.apply([result(str(i),False) for i in range(5)],seq=1,phase='extended'))
        self.assertTrue(self.state.should_close())

    def test_confirmed_failure_is_not_cancelled_before_stop_attempt(self):
        self.apply([result(str(i),False) for i in range(5)],seq=1,phase='extended')
        tokens={mode:alert['token'] for mode,alert in self.state.alerts.items()}
        self.apply([result('e'),result('f',False)],seq=3)
        self.assertTrue(self.state.should_close())
        self.state.acknowledge_close(tokens)
        self.assertFalse(self.state.should_close())

    def test_one_good_recheck_site_is_enough_when_none_mismatch(self):
        for position in range(3):
            samples=[result(str(i),i==position) for i in range(3)]
            self.apply(samples,seq=position+1,phase='recheck')
            self.assertFalse(self.state.should_close())

    def test_recheck_mismatch_overrides_two_good_sites(self):
        self.apply([result('a'),result('b'),result('c',False,outcome='exit_mismatch')],phase='recheck')
        self.assertTrue(self.state.should_close())

    def test_recheck_all_errors_waits_for_five_sites(self):
        self.apply([result('a',False),result('b',False),result('c',False)],phase='recheck')
        self.assertFalse(self.state.should_close())
        self.assertEqual(self.state.reason,'awaiting_five_site_verification')

    def test_extended_all_errors_closes(self):
        self.apply([result(str(i),False) for i in range(5)],phase='extended')
        self.assertTrue(self.state.should_close())
        self.assertEqual(self.state.close_reason(),'extended_verification_failed')

    def test_extended_one_good_anywhere_does_not_close(self):
        for position in range(5):
            self.apply([result(str(i),i==position) for i in range(5)],seq=position+1,phase='extended')
            self.assertFalse(self.state.should_close())

    def test_extended_mismatch_overrides_four_good_sites(self):
        self.apply([result(str(i),i!=2,**({'outcome':'exit_mismatch'} if i==2 else {}))
                    for i in range(5)],phase='extended')
        self.assertTrue(self.state.should_close())

    def test_extended_three_dispatch_slots_have_time_to_finish(self):
        self.assertTrue(self.apply([result(str(i)) for i in range(5)],phase='extended',
                                  started=self.now-watch.FRESH_FOR-1.1))

    def test_incomplete_or_duplicate_extended_group_cannot_decide(self):
        for samples in ([result(str(i),False) for i in range(4)],
                        [result('same',False) for _ in range(5)]):
            with self.assertRaises(ValueError):self.apply(samples,phase='extended')
        self.assertFalse(self.state.should_close())

    def test_recheck_staggered_requests_have_time_to_finish(self):
        self.assertTrue(self.apply([result('a'),result('b'),result('c')],
                                  phase='recheck',started=self.now-watch.FRESH_FOR-.1))

    def test_late_but_fresh_wrong_ip_cannot_be_masked_by_newer_good_round(self):
        self.apply([result('a'),result('b')],seq=3)
        self.assertTrue(self.state.observe_mismatch(0,1,self.now,
                        result('old',False,outcome='exit_mismatch'),'default_route'))
        self.assertTrue(self.state.should_close())

    def test_network_change_cannot_cancel_risk_already_confirmed(self):
        self.state.observe_mismatch(0,1,self.now,result('a',False,outcome='exit_mismatch'),'default_route')
        self.state.invalidate('network_changed')
        self.assertTrue(self.state.should_close())

    def test_old_epoch_or_expired_mismatch_ignored(self):
        for epoch,started in [(1,self.now),(0,self.now-watch.FRESH_FOR)]:
            self.assertFalse(self.state.observe_mismatch(epoch,1,started,
                             result('a',False,outcome='exit_mismatch'),'default_route'))
        self.assertFalse(self.state.should_close())

    def test_acknowledging_earlier_alert_does_not_remove_new_alert(self):
        self.state.observe_mismatch(0,1,self.now,result('a',False,outcome='exit_mismatch'),'default_route')
        tokens={'default_route':self.state.alerts['default_route']['token']}
        self.state.observe_mismatch(0,2,self.now,result('b',False,outcome='exit_mismatch'),'default_route')
        self.state.acknowledge_close(tokens)
        self.assertTrue(self.state.should_close())

    def test_single_or_duplicate_site_cannot_make_decision(self):
        for items in [[result('a',False)],[result('a',False),result('a',False)]]:
            with self.assertRaises(ValueError):self.apply(items)
            self.assertFalse(self.state.should_close())


class RotationTests(unittest.TestCase):
    def test_at_least_ten_distinct_sites(self):
        self.assertGreaterEqual(len(watch.SITES),10)
        self.assertEqual(len({urlsplit(s[1]).hostname for s in watch.SITES}),len(watch.SITES))
        self.assertEqual(len(watch.SITES)%2,0)

    def test_two_distinct_per_round_all_sites_covered(self):
        seen=set()
        for i in range(1,len(watch.SITES)//2+1):
            pair,mode=watch.select_pair(i)
            self.assertEqual(len(pair),2)
            self.assertNotEqual(pair[0][0],pair[1][0])
            seen.update(s[0] for s in pair)
        self.assertEqual(seen,{s[0] for s in watch.SITES})

    def test_every_site_uses_both_paths_across_two_cycles(self):
        paths={s[0]:set() for s in watch.SITES}
        for i in range(1,len(watch.SITES)+1):
            pair,mode=watch.select_pair(i)
            for s in pair:paths[s[0]].add(mode)
        self.assertTrue(all(v=={'default_route','nextin_proxy'} for v in paths.values()))

    def test_even_pair_pool_still_checks_each_site_over_both_paths(self):
        with patch.object(watch,'SITES',watch.SITES[:20]):
            paths={s[0]:set() for s in watch.SITES}
            for seq in range(1,21):
                pair,mode=watch.select_pair(seq)
                for site in pair:paths[site[0]].add(mode)
        self.assertTrue(all(p=={'default_route','nextin_proxy'} for p in paths.values()))


class ProcessTests(unittest.IsolatedAsyncioTestCase):
    def table(self):
        return {10:dict(ppid=1,path='/Applications/Claude.app/Contents/MacOS/Claude',birth=('first',)),
                11:dict(ppid=10,path='/usr/bin/curl',birth=('second',)),
                12:dict(ppid=11,path='/usr/bin/python3',birth=('third',)),
                20:dict(ppid=1,path='/Applications/Safari.app/Contents/MacOS/Safari',birth=('other',))}

    def test_unrelated_apps_excluded(self):
        self.assertEqual(watch.targets(self.table()),{10,11,12})

    async def test_pause_all_before_killing_any(self):
        with patch.object(watch,'process_table',return_value=self.table()),patch.object(watch.os,'kill') as kill:
            self.assertEqual(set(await watch.stop_apps(lambda: True)),{10,11,12})
        self.assertEqual([c.args[1] for c in kill.call_args_list],[signal.SIGSTOP]*3+[signal.SIGKILL]*3)

    async def test_reused_pid_not_signalled(self):
        before,after=self.table(),self.table();after[11]['birth']=('new',)
        with patch.object(watch,'process_table',side_effect=[before,after]),patch.object(watch.os,'kill') as kill:
            await watch.stop_apps(lambda: True)
        self.assertNotIn(11,[c.args[0] for c in kill.call_args_list])

    async def test_recovered_or_expired_evidence_cancels_after_discovery(self):
        for checks in ([False], [True, False]):
            with patch.object(watch,'process_table',return_value=self.table()), \
                 patch.object(watch.os,'kill') as kill:
                self.assertEqual(await watch.stop_apps(unittest.mock.Mock(side_effect=checks)), [])
            kill.assert_not_called()

    async def test_slow_discovery_does_not_block_probes_or_close_after_recovery(self):
        import threading
        started, release = threading.Event(), threading.Event()
        def slow_table():
            started.set()
            if not release.wait(2):raise RuntimeError('test failed to release worker')
            return self.table()
        allowed = [True]
        with patch.object(watch,'process_table',side_effect=slow_table), patch.object(watch.os,'kill') as kill:
            task = asyncio.create_task(watch.stop_apps(lambda: allowed[0]))
            try:
                self.assertTrue(await asyncio.to_thread(started.wait, 1))
                allowed[0] = False
            finally:
                release.set()
            self.assertEqual(await task, [])
        kill.assert_not_called()


class ProbeTests(unittest.IsolatedAsyncioTestCase):
    async def test_waits_for_second_site_before_deciding(self):
        event=asyncio.Event()
        async def fake(site,mode):
            if site[0]=='Cloudflare':raise TimeoutError('timed out')
            await event.wait();return watch.EXPECTED
        monitor=watch.Monitor()
        with patch.object(watch,'probe',fake):
            task=asyncio.create_task(monitor.check(0,1,time.monotonic()))
            await asyncio.sleep(.01)
            self.assertFalse(task.done());self.assertFalse(monitor.state.should_close())
            event.set();await task
        self.assertFalse(monitor.state.should_close())

    async def test_exactly_two_requests_on_same_path(self):
        calls=[]
        async def fake(site,mode):calls.append((site,mode));return watch.EXPECTED
        monitor=watch.Monitor()
        with patch.object(watch,'probe',fake):await monitor.check(0,2,time.monotonic())
        self.assertEqual(len(calls),2)
        self.assertEqual({mode for _,mode in calls},{'nextin_proxy'})

    async def test_both_fail_queues_three_additional_sites_with_detailed_errors(self):
        async def fake(site,mode):raise watch.CommandError(28,'Operation timed out after 3000 milliseconds')
        monitor=watch.Monitor()
        with patch.object(watch,'probe',fake),self.assertLogs(level='WARNING') as logs:
            await monitor.check(0,1,time.monotonic())
        self.assertFalse(monitor.state.should_close())
        self.assertEqual(len(monitor.recheck_queue),3)
        batch=monitor.rechecks['default_route']
        self.assertEqual(len(set(s[0] for s in batch.sites)),3)
        self.assertFalse(set(s[0] for s in batch.sites)&{'Cloudflare','ident.me'})
        self.assertTrue(all(r['command_exit']==28 for r in monitor.state.results))
        self.assertTrue(any('3000 milliseconds' in line and 'https://' in line for line in logs.output))

    async def test_wrong_ip_acts_before_other_site_finishes(self):
        event=asyncio.Event()
        async def fake(site,mode):
            if site[0]=='Cloudflare':return '198.51.100.7'
            await event.wait();return watch.EXPECTED
        monitor=watch.Monitor()
        with patch.object(watch,'probe',fake):
            task=asyncio.create_task(monitor.check(0,1,time.monotonic()))
            try:
                await asyncio.sleep(.01)
                self.assertFalse(task.done())
                self.assertTrue(monitor.state.should_close())
            finally:
                event.set();await task
        self.assertTrue(monitor.state.should_close())

    async def test_recheck_waits_for_all_three_and_uses_original_path(self):
        monitor=watch.Monitor()
        original=watch.ProbeRound(0,1,watch.SITES[:2],'nextin_proxy')
        monitor.sequence=1
        monitor.queue_recheck(original)
        batch=monitor.rechecks['nextin_proxy']
        calls=[]
        async def fake(site,mode):
            calls.append((site[0],mode));raise TimeoutError('timeout')
        with patch.object(watch,'probe',fake):
            await asyncio.gather(*monitor.dispatch())
            self.assertEqual(len(calls),2)
            self.assertFalse(monitor.state.should_close())
            self.assertEqual(monitor.status()['pending_rechecks']['nextin_proxy']['completed_sites'],2)
            await asyncio.gather(*monitor.dispatch())
        self.assertEqual(len(calls),3)
        self.assertEqual({m for _,m in calls},{'nextin_proxy'})
        self.assertFalse(monitor.state.should_close())
        self.assertEqual(monitor.rechecks['nextin_proxy'].phase,'extended')
        self.assertEqual(len(monitor.recheck_queue),5)
        self.assertFalse(set(s[0] for s in monitor.rechecks['nextin_proxy'].sites)
                         & ({s[0] for s in original.sites}|{s[0] for s in batch.sites}))

    async def test_recheck_one_good_no_recursion_or_close(self):
        monitor=watch.Monitor()
        original=watch.ProbeRound(0,1,watch.SITES[:2],'default_route')
        monitor.sequence=1;monitor.queue_recheck(original)
        selected=monitor.rechecks['default_route'].sites
        async def fake(site,mode):
            if site==selected[2]:return watch.EXPECTED
            raise TimeoutError('timeout')
        with patch.object(watch,'probe',fake):
            await asyncio.gather(*monitor.dispatch())
            await asyncio.gather(*monitor.dispatch())
        self.assertFalse(monitor.state.should_close())
        self.assertEqual(monitor.rechecks,{})
        self.assertEqual(len(monitor.recheck_queue),0)

    async def test_recheck_wrong_ip_does_not_wait_for_remaining_sites(self):
        monitor=watch.Monitor()
        original=watch.ProbeRound(0,1,watch.SITES[:2],'default_route')
        monitor.sequence=1;monitor.queue_recheck(original)
        selected=monitor.rechecks['default_route'].sites
        async def fake(site,mode):return '198.51.100.7' if site==selected[0] else watch.EXPECTED
        with patch.object(watch,'probe',fake):
            await asyncio.gather(*monitor.dispatch())
        self.assertTrue(monitor.state.should_close())
        self.assertEqual(len(monitor.recheck_queue),1)

    async def test_extended_one_good_clears_pending_without_another_stage(self):
        monitor=watch.Monitor()
        original=watch.ProbeRound(0,1,watch.SITES[:2],'default_route')
        monitor.sequence=1;monitor.queue_recheck(original)
        first=monitor.rechecks['default_route']
        async def fail(site,mode):raise TimeoutError('timeout')
        with patch.object(watch,'probe',fail):
            await asyncio.gather(*monitor.dispatch())
            await asyncio.gather(*monitor.dispatch())
        final=monitor.rechecks['default_route']
        self.assertEqual(final.phase,'extended')
        self.assertEqual(len({s[0] for s in (*original.sites,*first.sites,*final.sites)}),10)
        async def recover(site,mode):
            if site==final.sites[-1]:return watch.EXPECTED
            raise TimeoutError('timeout')
        with patch.object(watch,'probe',recover):
            for _ in range(3):await asyncio.gather(*monitor.dispatch())
        self.assertFalse(monitor.state.should_close())
        self.assertEqual(monitor.rechecks,{})
        self.assertEqual(len(monitor.recheck_queue),0)

    async def test_extended_wrong_ip_acts_before_remaining_three_sites(self):
        monitor=watch.Monitor()
        original=watch.ProbeRound(0,1,watch.SITES[:2],'default_route')
        monitor.sequence=1;monitor.queue_recheck(original)
        triple=monitor.rechecks['default_route']
        monitor.queue_recheck(triple)
        monitor.recheck_queue=watch.deque((batch,site) for batch,site in monitor.recheck_queue
                                        if batch.phase=='extended')
        selected=monitor.rechecks['default_route'].sites
        async def fake(site,mode):return '198.51.100.7' if site==selected[0] else watch.EXPECTED
        with patch.object(watch,'probe',fake):await asyncio.gather(*monitor.dispatch())
        self.assertTrue(monitor.state.should_close())
        self.assertEqual(len(monitor.recheck_queue),3)

    async def test_two_paths_expand_to_five_independently_and_share_request_slots(self):
        monitor=watch.Monitor()
        for seq,mode in enumerate(('default_route','nextin_proxy'),1):
            monitor.queue_recheck(watch.ProbeRound(0,seq,watch.SITES[:2],mode))
        calls=[]
        async def fail(site,mode):calls.append((site[0],mode));raise TimeoutError('timeout')
        with patch.object(watch,'probe',fail):
            while monitor.recheck_queue:
                before=len(calls)
                await asyncio.gather(*monitor.dispatch())
                self.assertLessEqual(len(calls)-before,2)
        self.assertEqual(len(calls),16)
        self.assertEqual(monitor.rechecks,{})
        self.assertEqual(set(monitor.state.alerts),{'default_route','nextin_proxy'})

    async def test_new_site_parsers_require_one_exact_visitor_ip(self):
        async def response(*args,**kw):return body[0]
        body=['']
        with patch.object(watch,'output',response):
            for text in ('{"ip":"103.131.112.53"}',):
                body[0]=text
                self.assertEqual(await watch.probe(('IPPure','https://my.ippure.com/v1/info','json_ip'),'default_route'),watch.EXPECTED)
            for text in ('{}','{"ip":123}','{"ip":["103.131.112.53"]}','{"ip":"not-an-ip"}'):
                body[0]=text
                item=await watch.probe_result(('IPPure','https://my.ippure.com/v1/info','json_ip'),'default_route')
                self.assertFalse(item['ok'])
            body[0]='<p>1.1.1.1</p><input name="query" value="103.131.112.53" id="query-input">'
            self.assertEqual(await watch.probe(('IPIP0','https://ipip0.net/en','ipip0_html'),'default_route'),watch.EXPECTED)
            for text in ('<p>103.131.112.53</p>', '<input id="query-input" name="query" value="">',body[0]*2):
                body[0]=text
                item=await watch.probe_result(('IPIP0','https://ipip0.net/en','ipip0_html'),'default_route')
                self.assertFalse(item['ok'])

    async def test_all_requests_share_two_per_second_slots(self):
        class End(Exception):pass
        original_sleep=asyncio.sleep
        tick=[0];calls=[]
        async def sleep(_):
            await original_sleep(0)
            tick[0]+=1
            if tick[0]==6:raise End()
        async def fake(site,mode):
            calls.append((tick[0],site[0],mode));raise TimeoutError('timeout')
        monitor=watch.Monitor()
        with patch.object(watch,'probe',fake),patch.object(watch.asyncio,'sleep',sleep):
            with self.assertRaises(End):await monitor.exit_loop()
            await asyncio.gather(*monitor.checks)
        from collections import Counter
        self.assertTrue(all(c<=2 for c in Counter(t for t,_,_ in calls).values()))
        self.assertEqual([sum(t==i for t,_,_ in calls) for i in range(3)],[2,2,1])
        self.assertEqual(len({s for t,s,_ in calls if t<3}),5)
        self.assertEqual([sum(t==i for t,_,_ in calls) for i in range(6)],[2,2,1,2,2,1])
        self.assertEqual(len({s for _,s,_ in calls}),10)
        self.assertTrue(monitor.state.should_close())

    async def test_pending_recheck_prevents_new_round_and_duplicate_recheck(self):
        monitor=watch.Monitor()
        original=watch.ProbeRound(0,1,watch.SITES[:2],'default_route')
        monitor.sequence=1;monitor.queue_recheck(original);monitor.queue_recheck(original)
        self.assertEqual(len(monitor.recheck_queue),3)
        monitor.recheck_queue.clear()
        self.assertEqual(monitor.dispatch(),[])

    async def test_two_paths_queue_six_rechecks_without_exceeding_two_per_slot(self):
        monitor=watch.Monitor()
        for seq,mode in enumerate(('default_route','nextin_proxy'),1):
            monitor.queue_recheck(watch.ProbeRound(0,seq,watch.SITES[:2],mode))
        calls=[]
        async def fake(site,mode):calls.append((site[0],mode));return watch.EXPECTED
        with patch.object(watch,'probe',fake):
            for _ in range(3):
                before=len(calls)
                await asyncio.gather(*monitor.dispatch())
                self.assertEqual(len(calls)-before,2)
        self.assertEqual(monitor.rechecks,{})
        self.assertEqual([sum(m==mode for _,m in calls)
                          for mode in ('default_route','nextin_proxy')],[3,3])

    async def test_network_change_discards_queued_and_inflight_recheck(self):
        monitor=watch.Monitor()
        original=watch.ProbeRound(0,1,watch.SITES[:2],'default_route')
        monitor.sequence=1;monitor.queue_recheck(original)
        batch=monitor.rechecks['default_route']
        monitor.invalidate('network_changed')
        async def fake(site,mode):return '198.51.100.7'
        with patch.object(watch,'probe',fake):await monitor.check_site(batch,batch.sites[0])
        self.assertFalse(monitor.state.should_close())
        self.assertFalse(monitor.rechecks)
        self.assertFalse(monitor.recheck_queue)

    async def test_proxy_cannot_retry_directly(self):
        calls=[]
        async def fake(args,**kw):calls.append(args);return '103.131.112.53\n'
        with patch.object(watch,'output',fake):
            self.assertEqual(await watch.probe(watch.SITES[1],'nextin_proxy'),watch.EXPECTED)
        args=calls[0]
        self.assertEqual(args[args.index('--proxy')+1],'http://[::1]:7890')
        self.assertEqual(args[args.index('--noproxy')+1],'')
        self.assertNotIn('--retry',args)

    async def test_invalid_response_logged_as_error(self):
        async def fake(args,**kw):return '<html>error</html>'
        with patch.object(watch,'output',fake):item=await watch.probe_result(watch.SITES[0],'default_route')
        self.assertFalse(item['ok']);self.assertEqual(item['error_type'],'ValueError')

    async def test_startup_safety_loop_does_not_kill(self):
        class End(Exception):pass
        async def sleep(_):raise End()
        monitor=watch.Monitor()
        with patch.object(watch,'stop_apps') as stop,patch.object(watch,'write_status'),patch.object(watch.asyncio,'sleep',sleep):
            with self.assertRaises(End):await monitor.safety_loop()
        stop.assert_not_called()


class SafetyTests(unittest.IsolatedAsyncioTestCase):
    async def pass_once(self,monitor):
        class End(Exception):pass
        async def sleep(_):raise End()
        with patch.object(watch,'write_status'),patch.object(watch.asyncio,'sleep',sleep):
            with self.assertRaises(End):await monitor.safety_loop()

    async def test_no_process_signals_until_all_five_final_checks_fail(self):
        monitor=watch.Monitor()
        async def fake(site,mode):raise TimeoutError('timeout')
        table={10:dict(ppid=1,path='/Applications/Claude.app/Contents/MacOS/Claude',birth=('first',))}
        with patch.object(watch,'probe',fake),patch.object(watch,'process_table',return_value=table), \
             patch.object(watch.os,'kill') as kill:
            await monitor.check(0,1,time.monotonic())
            await self.pass_once(monitor)
            kill.assert_not_called()
            await asyncio.gather(*monitor.dispatch())
            await self.pass_once(monitor)
            kill.assert_not_called()
            await asyncio.gather(*monitor.dispatch())
            await self.pass_once(monitor)
            kill.assert_not_called()
            for _ in range(2):
                await asyncio.gather(*monitor.dispatch())
                await self.pass_once(monitor)
                kill.assert_not_called()
            await asyncio.gather(*monitor.dispatch())
            await self.pass_once(monitor)
            self.assertEqual([c.args for c in kill.call_args_list],
                             [(10,signal.SIGSTOP),(10,signal.SIGKILL)])

    async def test_wrong_ip_reaches_stop_loop_while_peer_is_pending(self):
        event=asyncio.Event()
        async def fake(site,mode):
            if site[0]=='Cloudflare':return '198.51.100.7'
            await event.wait();return watch.EXPECTED
        monitor=watch.Monitor()
        with patch.object(watch,'probe',fake),patch.object(watch,'stop_apps',new_callable=AsyncMock,return_value=[]) as stop:
            task=asyncio.create_task(monitor.check(0,1,time.monotonic()))
            try:
                await asyncio.sleep(.01)
                await self.pass_once(monitor)
                stop.assert_awaited_once()
                self.assertFalse(task.done())
            finally:
                event.set();await task

    async def test_stop_error_retains_alert_for_retry(self):
        monitor=watch.Monitor()
        monitor.state.observe_mismatch(0,1,time.monotonic(),
                                       result('a',False,outcome='exit_mismatch'),'default_route')
        with patch.object(watch,'stop_apps',new_callable=AsyncMock,
                          side_effect=watch.subprocess.TimeoutExpired('ps',2)),self.assertLogs(level='ERROR'):
            await self.pass_once(monitor)
        self.assertTrue(monitor.state.should_close())
        self.assertTrue(monitor.state.alerts)

    async def test_manual_check_rechecks_without_sending_signals(self):
        original_sleep=asyncio.sleep
        async def sleep(_):await original_sleep(0)
        async def fake(site,mode):raise TimeoutError('timeout')
        with patch.object(watch,'probe',fake),patch.object(watch.asyncio,'sleep',sleep), \
             patch.object(watch.os,'kill') as kill,patch('builtins.print'):
            self.assertFalse(await watch.check_once())
        kill.assert_not_called()

    async def test_manual_check_overlaps_slow_probes_so_final_results_are_not_stale(self):
        calls=[]
        async def slow(site,mode):
            calls.append(site[0]);await asyncio.sleep(.1);raise TimeoutError('simulated timeout')
        with patch.object(watch,'INTERVAL',.04),patch.object(watch,'FRESH_FOR',.14), \
             patch.object(watch,'probe',slow),patch.object(watch.os,'kill') as kill,patch('builtins.print'):
            self.assertFalse(await watch.check_once())
        self.assertEqual(len(calls),10)
        self.assertEqual(len(set(calls)),10)
        kill.assert_not_called()


if __name__=='__main__':unittest.main(verbosity=2)
