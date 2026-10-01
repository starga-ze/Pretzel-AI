"""Run with python -m unittest discover -s tests. DB tests require PZ_TEST_DSN."""
import os
import threading
import unittest
from unittest.mock import patch

from src.crawler import extract, sitemap, pipeline, store
from src.crawler.fetch import Result, Cancelled, _Redirect, retry_after, fetch, FetchError

BASE = 'https://docs.paloaltonetworks.com'


def topic(body, heading='Example'):
    return '<html><title>Example</title><div class="book-pdf-content"><div class="topic concept" id="topic"><h1>' + heading + '</h1>' + body + '</div></div></html>'


class ExtractionTests(unittest.TestCase):
    def test_technical_table_and_code_keep_structure(self):
        doc = extract.analyze(topic('<table><tr><th>Setting</th><th>Description</th></tr><tr><td>HIP</td><td>Enable matching</td></tr></table><pre>set foo\n  bar</pre><!-- invisible -->'))
        self.assertEqual(doc.decision,'collected')
        self.assertIn('| HIP | Enable matching |',doc.text)
        self.assertIn('set foo\n  bar',doc.text)
        self.assertNotIn('invisible',doc.text)

    def test_navigation_is_not_a_technical_topic(self):
        doc = extract.analyze(topic('<p>The following topics describe the settings.</p><ul data-outputclass="nav"><li><a href="/a">Settings</a></li></ul>'))
        self.assertEqual((doc.decision,doc.reason),('excluded','navigation_only'))

    def test_short_fix_is_preserved(self):
        self.assertEqual(extract.analyze(topic('<p>PAN-123: Fixed a crash.</p>')).decision,'collected')

    def test_incomplete_and_unknown_templates_are_not_deletion_evidence(self):
        self.assertEqual(extract.analyze('<h1>Loading</h1>').decision,'unknown')
        self.assertEqual(extract.analyze(topic('')).decision,'unknown')
        self.assertEqual(extract.analyze('<div class="oneColumnPlain"><p>Unknown template</p></div>').decision,'unknown')

    def test_feature_note_template(self):
        doc=extract.analyze('<main class="td-body__content"><div class="new-features-entry"><div class="coveo-results-card"><h2>New command</h2><div class="coveo-results-content"><p>Use show to inspect state.</p></div><div class="coveo-results-tag-list">Marketing tags</div></div></div></main>')
        self.assertEqual(doc.decision,'collected')
        self.assertNotIn('Marketing tags',doc.text)

    def test_menu_and_inline_links(self):
        doc=extract.analyze(topic('<p><span class="menucascade"><span>Objects</span><span>HIP</span></span> — see <a href="/ngfw/help">help</a>.</p>'),BASE+'/ngfw/a/b')
        self.assertIn('Objects → HIP',doc.text)
        self.assertIn('[help]('+BASE+'/ngfw/help)',doc.text)


class DiscoveryTests(unittest.TestCase):
    def test_both_version_layouts(self):
        for url in ['/pan-os/12-1/admin/foo','/ngfw/help/12-1/foo']:
            self.assertEqual(sitemap.classify(BASE+url)['version'],'12-1')
        self.assertEqual(sitemap.classify(BASE+'/pan-os/12-1/admin/foo')['docset'],'admin')

    def test_host_checks_and_fragment_dedup(self):
        self.assertEqual(sitemap.canonical(BASE+'/ngfw//help/#anchor'),BASE+'/ngfw/help')
        for url in ['https://evil.example/x','https://docs.paloaltonetworks.com.evil/x','https://user@docs.paloaltonetworks.com/x','file:///etc/passwd']:
            with self.assertRaises(ValueError): sitemap.canonical(url)

    def test_index_and_namespace_and_missing_lastmod(self):
        bodies={BASE+'/sitemap.xml':'<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><sitemap><loc>'+BASE+'/child.xml</loc></sitemap></sitemapindex>', BASE+'/child.xml':'<urlset><url><loc>'+BASE+'/ngfw/help/a#one</loc></url><url><loc>'+BASE+'/ngfw/help/a#two</loc><lastmod>2026-09-01</lastmod></url></urlset>'}
        with patch('src.crawler.fetch.download',side_effect=lambda u,**kw:(200,bodies[u],u)):
            pages=sitemap.fetch(max_age=0)
        self.assertEqual(len(pages),1)
        self.assertIsNotNone(next(iter(pages.values()))['lastmod'])

    def test_invalid_or_empty_sitemap_fails_closed(self):
        for body in ['<html>error</html>','<urlset/>','<urlset><url>']:
            with patch('src.crawler.fetch.download',return_value=(200,body,BASE+'/sitemap.xml')):
                with self.assertRaises(Exception): sitemap.fetch(max_age=0)

    def test_retry_after_is_bounded(self):
        self.assertEqual(retry_after('900'),120)
        self.assertEqual(retry_after('bad'),0)


class TransportTests(unittest.TestCase):
    def test_missing_is_distinct_from_temporary_failure(self):
        url=BASE+'/ngfw/help/topic'
        with patch('src.crawler.fetch.download',return_value=(404,'',url)):
            self.assertEqual(fetch(url).decision,'excluded')
        with patch('src.crawler.fetch.download',side_effect=FetchError('HTTP 503',503)):
            result=fetch(url)
            self.assertEqual((result.decision,result.status),('unknown',503))

    def test_redirect_to_external_host_is_refused_before_request(self):
        import urllib.request
        req=urllib.request.Request(BASE+'/ngfw/help/a')
        with self.assertRaises(ValueError):
            _Redirect().redirect_request(req,None,302,'Found',{},'https://evil.example/topic')

    def test_cancellation_interrupts_retry_wait(self):
        from src.crawler.fetch import pause
        event=threading.Event();event.set()
        with self.assertRaises(Cancelled): pause(120,event)


@unittest.skipUnless(os.environ.get('PZ_TEST_DSN'), 'PZ_TEST_DSN points to a disposable database')
class LifecycleTests(unittest.TestCase):
    def setUp(self):
        import psycopg
        self.conn=psycopg.connect(os.environ['PZ_TEST_DSN'])
        self.assertEqual(self.conn.info.dbname,'corpus_test')
        self.conn.execute('DROP SCHEMA IF EXISTS techdoc CASCADE; CREATE SCHEMA techdoc')
        self.conn.execute('''CREATE TABLE techdoc.document(url TEXT PRIMARY KEY,title TEXT NOT NULL,text TEXT NOT NULL,content_sha BYTEA NOT NULL,char_count INTEGER NOT NULL,lastmod TIMESTAMPTZ,fetched_at TIMESTAMPTZ NOT NULL DEFAULT now());
            CREATE TABLE techdoc.crawl_run(id BIGSERIAL PRIMARY KEY,started_at TIMESTAMPTZ NOT NULL DEFAULT now(),finished_at TIMESTAMPTZ,status TEXT NOT NULL DEFAULT 'running',listed INTEGER NOT NULL DEFAULT 0,stored INTEGER NOT NULL DEFAULT 0,rejected INTEGER NOT NULL DEFAULT 0,error TEXT)''')
        self.conn.commit();store.migrate(self.conn)
        self.urls=[BASE+'/ngfw/help/12-1/topic-'+str(i) for i in range(20)]
        with self.conn.cursor() as cur:
            for url in self.urls: store.put(cur,url,'Technical topic','Useful technical body',None)
        self.conn.commit()

    def tearDown(self): self.conn.close()

    def run_crawl(self, outcomes=None, dry_run=False, scope=None):
        pages={u:dict(sitemap.classify(u),lastmod=None) for u in self.urls}
        outcomes=outcomes or {}
        def get(u,cancel):
            return outcomes.get(u,Result(u,u,200,'collected','technical_topic','Technical topic','Useful technical body'))
        with patch.object(sitemap,'fetch',return_value=pages),patch.object(pipeline,'fetch',side_effect=get):
            return list(pipeline.crawl(self.conn,scope,dry_run))[-1]

    def active(self): return store.known_urls(self.conn)

    def test_a_database_on_the_old_vocabulary_is_refused_before_any_fetch(self):
        # The failure this replaces: a deploy without the migration started normally and died on
        # the first page with a CHECK violation, having already spent the fetches.
        self.conn.execute('ALTER TABLE techdoc.crawl_observation DROP CONSTRAINT crawl_observation_decision_check')
        self.conn.execute("""ALTER TABLE techdoc.crawl_observation ADD CONSTRAINT
            crawl_observation_decision_check CHECK (decision IN ('document','non_document','unavailable','unknown'))""")
        self.conn.commit()
        with self.assertRaisesRegex(RuntimeError, 'migration required'):
            store.claim(self.conn)
        # Refused, not half-claimed: the lock is free and the corpus untouched.
        store.migrate(self.conn)
        run = store.claim(self.conn)
        store.finish_run(self.conn, run, 'cancelled', {}); store.release(self.conn)
        self.assertEqual(len(self.active()), 20)

    def test_migration_rewrites_the_old_outcome_names(self):
        # Runs recorded before the vocabulary was unified are rewritten rather than read through a
        # compatibility shim, so "Last result" on an old run shows the same words as a new one.
        self.conn.execute("""INSERT INTO techdoc.crawl_run(id,status,summary) VALUES (99,'ok',
            '{"stored":21476,"rejected":298,"unavailable":214,"unknown":207,"done":22195,"processed":22195}')""")
        self.conn.execute('ALTER TABLE techdoc.crawl_observation DROP CONSTRAINT crawl_observation_decision_check')
        for decision, reason in [('document','technical_topic'),('non_document','navigation_only'),
                                 ('unavailable','http_404'),('unknown','unsupported_template')]:
            self.conn.execute('INSERT INTO techdoc.crawl_observation(run_id,url,final_url,decision,reason)'
                              ' VALUES (99,%s,%s,%s,%s)',('u-'+reason,'u-'+reason,decision,reason))
        self.conn.commit()
        store.migrate(self.conn)
        self.assertEqual({r[0] for r in self.conn.execute(
            'SELECT DISTINCT decision FROM techdoc.crawl_observation WHERE run_id=99')},
            {'collected','excluded','unknown'})
        summary = self.conn.execute('SELECT summary FROM techdoc.crawl_run WHERE id=99').fetchone()[0]
        # The two old exclusion counters add up; `done` goes because it copied `processed`.
        self.assertEqual(summary, {'collected':21476,'excluded':512,'unknown':207,'processed':22195})
        store.migrate(self.conn)
        self.assertEqual(self.conn.execute('SELECT summary FROM techdoc.crawl_run WHERE id=99').fetchone()[0], summary)

    def test_migration_is_repeatable_and_lock_is_cross_process(self):
        store.migrate(self.conn)
        run=store.claim(self.conn)
        import psycopg
        with psycopg.connect(os.environ['PZ_TEST_DSN']) as other:
            with self.assertRaisesRegex(RuntimeError,'already running'): store.claim(other)
        store.finish_run(self.conn,run,'cancelled',{});store.release(self.conn)

    def test_small_product_and_unknown_survive(self):
        small=BASE+'/small/manual/a'
        with self.conn.cursor() as cur: store.put(cur,small,'Small','Real technical body',None)
        self.conn.commit()
        result=self.run_crawl({self.urls[0]:Result(self.urls[0],self.urls[0],503,'unknown','fetch_failed')})
        self.assertIn(small,self.active());self.assertIn(self.urls[0],self.active())
        # Pages this crawler could not read are an ordinary outcome, not an abnormal run: over a
        # full sitemap they are never none, so warning on them made every run say the same word.
        self.assertEqual(result['counts']['warning'],'')
        self.assertEqual(store.status(self.conn)['last_run_status'],'ok')

    def test_archive_and_restore_confirmed_non_document(self):
        url=self.urls[0]
        result=self.run_crawl({url:Result(url,url,200,'excluded','navigation_only')})
        self.assertEqual(result['counts']['removed'],1);self.assertNotIn(url,self.active())
        archive_id=self.conn.execute('SELECT id FROM techdoc.document_archive WHERE url=%s',(url,)).fetchone()[0]
        self.assertEqual(store.restore(self.conn,archive_id),url)
        self.assertEqual(store.restore(self.conn,archive_id),None)

    def test_dry_run_does_not_change_active_corpus(self):
        url=self.urls[0]
        before=self.conn.execute('SELECT url,text,fetched_at FROM techdoc.document ORDER BY url').fetchall()
        result=self.run_crawl({url:Result(url,url,200,'excluded','navigation_only')},dry_run=True)
        self.assertEqual(result['counts']['candidates'],1)
        self.assertEqual(before,self.conn.execute('SELECT url,text,fetched_at FROM techdoc.document ORDER BY url').fetchall())

    def test_missing_requires_two_runs_at_least_a_day_apart(self):
        url=self.urls[0];bad={url:Result(url,url,404,'excluded','http_404')}
        self.run_crawl(bad);self.assertIn(url,self.active())
        self.conn.execute("UPDATE techdoc.crawl_observation SET observed_at=now()-interval '25 hours'");self.conn.commit()
        self.run_crawl(bad);self.assertNotIn(url,self.active())

    def test_sitemap_absence_does_not_remove_document(self):
        other=BASE+'/ngfw/help/12-1/not-in-sitemap'
        with self.conn.cursor() as cur: store.put(cur,other,'Still online','Useful technical body',None)
        self.conn.commit();self.run_crawl();self.assertIn(other,self.active())

    def test_mass_removal_is_deferred(self):
        result=self.run_crawl({u:Result(u,u,200,'excluded','navigation_only') for u in self.urls})
        self.assertEqual(result['counts']['removed'],0)
        self.assertTrue(result['counts']['cleanup_deferred']);self.assertEqual(len(self.active()),20)

    def test_product_wide_url_move_is_not_a_removal_risk(self):
        # The publisher moved a whole product (ai-runtime-security -> prisma-airs). Every page is
        # an alias whose destination this run stored, so nothing is lost and cleanup must proceed.
        moved = {u: Result(u,u.replace('/ngfw/help/','/prisma-airs/help/'),200,'collected',
                           'technical_topic','Title','Useful technical body') for u in self.urls}
        result = self.run_crawl(moved)
        self.assertEqual(result['counts']['warning'],'')
        self.assertFalse(result['counts']['cleanup_deferred'])
        self.assertEqual(result['counts']['removed'],20)
        self.assertEqual(self.active(),{u.replace('/ngfw/help/','/prisma-airs/help/') for u in self.urls})

    def test_a_move_does_not_mask_a_real_removal_beside_it(self):
        # The exemption is for aliases only: a product losing real pages in the same run must
        # still defer, or one reorganisation would wave through every deletion behind it.
        gone = BASE+'/pan-os/11-1/admin/a'
        with self.conn.cursor() as cur: store.put(cur,gone,'Doomed','Useful technical body',None)
        self.conn.commit()
        outcomes = {u: Result(u,u.replace('/ngfw/help/','/prisma-airs/help/'),200,'collected',
                              'technical_topic','Title','Useful technical body') for u in self.urls}
        outcomes[gone] = Result(gone,gone,200,'excluded','navigation_only')
        result = self.run_crawl(outcomes)
        self.assertIn('pan-os',result['counts']['warning'])
        self.assertEqual(result['counts']['removed'],0)
        self.assertIn(gone,self.active())

    def test_excluded_root_empties_its_whole_tree(self):
        # Emptying the tree is the point of excluding a root, so the per-product gate - which
        # would otherwise read "every page of this product is going" as the site losing it -
        # must not stop it.
        for url in [BASE+'/oss-listings/pan-os/a', BASE+'/resources/edl-hosting-service']:
            with self.conn.cursor() as cur: store.put(cur,url,'Licence text','Useful technical body',None)
        self.conn.commit()
        result = self.run_crawl()
        self.assertEqual(result['counts']['warning'],'')
        self.assertEqual(result['counts']['removed'],2)
        self.assertFalse([u for u in self.active() if '/oss-listings/' in u or '/resources/' in u])

    def test_a_policy_exclusion_still_answers_to_the_corpus_wide_cap(self):
        # Exempting policy from the per-product gate leaves the 10% gate as the only thing
        # between a mistyped root and a deleted product, so it has to hold.
        doomed = [BASE+'/pan-os/11-1/admin/topic-'+str(i) for i in range(6)]
        with self.conn.cursor() as cur:
            for url in doomed: store.put(cur,url,'Real documentation','Useful technical body',None)
        self.conn.commit()
        with patch.object(sitemap,'EXCLUDED_ROOTS',sitemap.EXCLUDED_ROOTS | {'pan-os'}):
            result = self.run_crawl()
        self.assertIn('10%',result['counts']['warning'])
        self.assertEqual(result['counts']['removed'],0)
        for url in doomed: self.assertIn(url,self.active())

    def test_exceptions_name_the_urls_and_keep_the_three_kinds_apart(self):
        # The counts say how many; this is what lets an operator open the page and disagree.
        skipped,missing,unread = self.urls[0],self.urls[1],self.urls[2]
        self.run_crawl({skipped:Result(skipped,skipped,200,'excluded','navigation_only'),
                        missing:Result(missing,missing,404,'excluded','http_404'),
                        unread:Result(unread,unread,503,'unknown','fetch_failed')})
        rows,total,tally,run_id = store.exceptions(self.conn)
        self.assertEqual(total,3)
        self.assertEqual({r['url'] for r in rows},{skipped,missing,unread})
        counted = {t['reason']:(t['decision'],t['count']) for t in tally}
        self.assertEqual({r:counted[r] for r in ('navigation_only','http_404','fetch_failed')},
            {'navigation_only':('excluded',1),'http_404':('excluded',1),'fetch_failed':('unknown',1)})
        # Collected pages are not exceptions, and a reason filter narrows to exactly one kind.
        self.assertEqual(store.exceptions(self.conn,reason='http_404')[1],1)
        self.assertEqual(store.exceptions(self.conn,reason='navigation_only')[0][0]['url'],skipped)
        # Every reason is reported, including those that did not occur: a zero says the check ran
        # and found nothing, which an absent row cannot. technical_topic is not an exception.
        self.assertEqual(set(counted),
                         {r for r,bucket in extract.REASONS.items() if bucket != extract.COLLECTED})
        self.assertEqual(counted['image_only_topic'],('unknown',0))
        # Occurred first, so the counts that matter are not buried under the ones at zero.
        self.assertEqual([t['count'] for t in tally][:4],[1,1,1,0])
        # Newest first. A crawl walks its worklist in URL order, so ordering these by URL too
        # pinned the page to the run's alphabetical head and nothing found later could enter it.
        self.conn.execute("UPDATE techdoc.crawl_observation SET observed_at=now()-interval '1 hour'"
                          ' WHERE url=%s',(skipped,))
        self.conn.commit()
        self.assertEqual(store.exceptions(self.conn)[0][-1]['url'],skipped)

    def test_cancel_before_discovery_releases_lock_and_never_prunes(self):
        gen=pipeline.crawl(self.conn);next(gen);gen.close()
        self.assertEqual(len(self.active()),20)
        self.assertEqual(store.status(self.conn)['last_run_status'],'cancelled')
        run=store.claim(self.conn);store.finish_run(self.conn,run,'cancelled',{});store.release(self.conn)

    def test_cancel_at_reconcile_never_prunes(self):
        pages={u:dict(sitemap.classify(u),lastmod=None) for u in self.urls}
        cancel=threading.Event()
        def get(u,c): return Result(u,u,200,'excluded','navigation_only') if u==self.urls[0] else Result(u,u,200,'collected','technical_topic','Title','Body')
        with patch.object(sitemap,'fetch',return_value=pages),patch.object(pipeline,'fetch',side_effect=get):
            gen=pipeline.crawl(self.conn,cancel=cancel)
            for event in gen:
                if event['stage']=='reconcile':
                    cancel.set()
                    with self.assertRaises(Cancelled): next(gen)
                    break
        self.assertEqual(len(self.active()),20)

    def test_closing_after_final_does_not_relabel_success_as_cancelled(self):
        pages={u:dict(sitemap.classify(u),lastmod=None) for u in self.urls}
        with patch.object(sitemap,'fetch',return_value=pages),patch.object(pipeline,'fetch',side_effect=lambda u,c:Result(u,u,200,'collected','technical_topic','Title','Body')):
            gen=pipeline.crawl(self.conn)
            for event in gen:
                if event['final']:
                    gen.close();break
        self.assertEqual(store.status(self.conn)['last_run_status'],'ok')

    def test_successful_alias_is_archived_only_after_target_accepted(self):
        source=self.urls[0];target=self.urls[1]
        self.run_crawl({source:Result(source,target,503,'unknown','fetch_failed')})
        self.assertIn(source,self.active())
        result=self.run_crawl({source:Result(source,target,200,'collected','technical_topic','Title','Body')})
        self.assertEqual(result['counts']['removed'],1)
        self.assertNotIn(source,self.active());self.assertIn(target,self.active())

    def test_unversioned_category_does_not_include_versioned_documents(self):
        url=BASE+'/ngfw/help/plain'
        with self.conn.cursor() as cur: store.put(cur,url,'Unversioned','Useful content',None)
        self.conn.commit()
        rows,total=store.documents(self.conn,'ngfw','help',version='')
        self.assertEqual(total,1);self.assertEqual(rows[0]['url'],url)
        self.assertEqual(store.documents(self.conn,'ngfw','help')[1],21)

    def test_unknown_observation_breaks_missing_confirmation(self):
        url=self.urls[0]
        self.run_crawl({url:Result(url,url,404,'excluded','http_404')})
        self.conn.execute("UPDATE techdoc.crawl_observation SET observed_at=now()-interval '25 hours'");self.conn.commit()
        self.run_crawl({url:Result(url,url,503,'unknown','fetch_failed')})
        self.run_crawl({url:Result(url,url,404,'excluded','http_404')})
        self.assertIn(url,self.active())

    def test_redirect_outside_scope_does_not_mutate_other_product(self):
        source=self.urls[0];target=BASE+'/pan-os/11-1/admin/a'
        self.run_crawl({source:Result(source,target,200,'collected','technical_topic','Title','Body')},scope='ngfw')
        self.assertIn(source,self.active());self.assertNotIn(target,self.active())

    def test_failed_discovery_preserves_existing_corpus_and_releases_lock(self):
        with patch.object(sitemap,'fetch',side_effect=ValueError('Truncated XML')):
            with self.assertLogs(pipeline.log,level='ERROR'):
                event=list(pipeline.crawl(self.conn))[-1]
        self.assertEqual(event['stage'],'failed');self.assertEqual(len(self.active()),20)
        run=store.claim(self.conn);store.finish_run(self.conn,run,'cancelled',{});store.release(self.conn)

    def test_scope_and_version_browse_and_literal_search(self):
        other=BASE+'/pan-os/11-1/admin/a'
        with self.conn.cursor() as cur: store.put(cur,other,'100% coverage','Useful content',None)
        self.conn.commit()
        self.run_crawl(scope='ngfw');self.assertIn(other,self.active())
        rows,total=store.documents(self.conn,'ngfw','help',version='12.1',limit=5)
        self.assertEqual(total,20);self.assertEqual(len(rows),5)
        rows,total=store.documents(self.conn,query='%');self.assertEqual(total,1)
        self.assertEqual(rows[0]['url'],other)


if __name__=='__main__': unittest.main()
