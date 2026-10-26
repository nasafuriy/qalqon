// Package report renders a compliance assessment. Two shapes are produced
// because two different people read it: the HTML report is the artifact a
// manager or auditor opens, and the text summary is the thing a developer
// sees in a terminal after a scan.
package report

import (
	"html/template"
	"io"
	"strconv"

	"github.com/nasafuriy/qalqon/internal/compliance"
)

// htmlData is what the HTML template receives.
type htmlData struct {
	Res    compliance.Result
	Groups []group
}

// group folds each three-valued status into a section the template can
// style with one class name, and carries the banner title.
type group struct {
	Status   compliance.Status
	Title    string
	Count    int
	Controls []compliance.Assessed
}

var statusTitle = map[compliance.Status]string{
	compliance.Fail:   "Not supporting the requirement",
	compliance.Pass:   "Supporting the requirement",
	compliance.Review: "Requires review outside this scan",
}

var htmlSrc = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Res.Title}} — {{.Res.ID}}</title>
<style>
  :root { --ok:#1a7f37; --bad:#cf222e; --review:#9a6700; }
  body { margin:0; font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif; color:#1f2328; background:#f6f8fa; }
  main { max-width:960px; margin:0 auto; padding:32px 20px 64px; }
  header { border-bottom:1px solid #d0d7de; padding-bottom:20px; margin-bottom:28px; }
  h1 { font-size:22px; margin:0 0 4px; }
  .score { font-size:15px; color:#57606a; }
  .score b { font-size:22px; color:#1f2328; }
  section { background:#fff; border:1px solid #d0d7de; border-radius:6px; margin-bottom:20px; overflow:hidden; }
  section h2 { font-size:14px; margin:0; padding:10px 16px; border-bottom:1px solid #d0d7de; }
  section.pass h2 { color:var(--ok); }
  section.fail h2 { color:var(--bad); }
  section.review h2 { color:var(--review); }
  section.fail { border-left:3px solid var(--bad); }
  section.pass { border-left:3px solid var(--ok); }
  section.review { border-left:3px solid var(--review); }
  dl { margin:0; padding:0 16px 12px; }
  dt { padding-top:12px; font-weight:600; }
  dd { margin:2px 0 0 0; }
  dd .rules { color:#57606a; font-size:13px; }
  dd ul { margin:6px 0 0 0; padding-left:18px; }
  dd li { margin:2px 0; }
  .where { font-family:ui-monospace,SFMono-Regular,Consolas,monospace; font-size:13px; }
  .fixable { color:#57606a; font-size:12px; }
  .reason { color:#57606a; font-style:italic; }
  footer { color:#57606a; font-size:13px; margin-top:32px; }
</style>
</head>
<body>
<main>
<header>
  <h1>{{.Res.Title}}</h1>
  <p class="score">
  {{if eq .Res.Score -1}}
      Nothing in this tree was applicable to the mapped controls.
  {{else}}
      Score <b>{{.Res.Score}}%</b> — {{.Res.Passed}} pass, {{.Res.Failed}} fail, {{.Res.Reviewed}} need review.
  {{end}}
  </p>
</header>
{{range .Groups}}
<section class="{{.Status}}">
  <h2>{{.Count}} · {{.Title}}</h2>
  <dl>
  {{range .Controls}}
    <dt>{{.ID}} — {{.Title}}</dt>
    <dd>
      <span class="rules">rules: {{range $i, $r := .Rules}}{{if $i}}, {{end}}{{$r}}{{end}}</span>
      {{if .Reason}}<div class="reason">{{.Reason}}</div>{{end}}
      {{if .Findings}}
      <ul>
      {{range .Findings}}
        <li><span class="where">{{.Where}}{{if .Line}}:{{.Line}}{{end}}</span> — {{.Name}}
        {{if .Fixable}}<span class="fixable">(fixable: qalqon scan -fix)</span>{{end}}</li>
      {{end}}
      </ul>
      {{end}}
    </dd>
  {{end}}
  </dl>
</section>
{{end}}
<footer>Generated from a static scan of the working tree. Controls needing runtime
evidence are marked review — a scan cannot answer for what it cannot see.</footer>
</main>
</body>
</html>
`

var htmlTmpl = template.Must(template.New("report").Parse(htmlSrc))

// HTML writes a standalone report document: no assets, no scripts, one file
// that opens in any browser years from now.
func HTML(w io.Writer, res compliance.Result) error {
	buckets := make(map[compliance.Status][]compliance.Assessed)
	for _, c := range res.Controls {
		buckets[c.Status] = append(buckets[c.Status], c)
	}

	data := htmlData{Res: res}
	for _, s := range []compliance.Status{compliance.Fail, compliance.Pass, compliance.Review} {
		if len(buckets[s]) == 0 {
			continue
		}
		data.Groups = append(data.Groups, group{Status: s, Title: statusTitle[s], Count: len(buckets[s]), Controls: buckets[s]})
	}
	return htmlTmpl.Execute(w, data)
}

// Text writes the terminal summary.
func Text(w io.Writer, res compliance.Result) {
	title := res.ID
	if res.Title != "" {
		title = res.Title
	}
	if res.Score < 0 {
		io.WriteString(w, "compliance · "+title+
			" · nothing in this tree applies to its controls\n\n")
		return
	}
	io.WriteString(w, "compliance · "+title+"\n")
	io.WriteString(w, "score "+strconv.Itoa(res.Score)+"% — "+strconv.Itoa(res.Passed)+
		" pass, "+strconv.Itoa(res.Failed)+" fail, "+strconv.Itoa(res.Reviewed)+" review\n\n")

	for _, c := range res.Controls {
		status := "REVIEW"
		switch c.Status {
		case compliance.Fail:
			status = "FAIL"
		case compliance.Pass:
			status = "PASS"
		}
		io.WriteString(w, status+"  "+c.ID+"  "+c.Title+"\n")
		if c.Status == compliance.Fail {
			for _, f := range c.Findings {
				at := f.Where()
				if f.Line > 0 {
					at += ":" + strconv.Itoa(f.Line)
				}
				io.WriteString(w, "        "+f.TemplateID+" → "+at+" · "+f.Name+"\n")
			}
		}
	}
}
