-- Name the four things a case detail actually shows.
--
-- The old names described their storage rather than their meaning: `reply` and `request_json` say
-- "a string" and "some JSON", and a reader of the drawer has to work out which of them is the
-- prompt that was sent and which is the whole envelope around it. The console shows them as
-- Request (prompt) / Response / Raw request / Raw response, and the columns now say the same.
ALTER TABLE benchmark.run_case RENAME COLUMN reply TO response;
ALTER TABLE benchmark.run_case RENAME COLUMN request_json TO raw_request;
ALTER TABLE benchmark.run_case RENAME COLUMN response_json TO raw_response;
