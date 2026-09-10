<#
.SYNOPSIS
    Validate a GitHub fork PR by publishing its exact head commit to a validation branch in the
    upstream microsoft-ui-xaml repo — WITHOUT opening a shadow pull request.

.DESCRIPTION
    Alternative to scripts/PromoteForkPR.ps1. Both solve the same problem: fork PRs get no pipeline
    secrets, so WinUI-GitHub-PR (OneBranch) dies at "Install Pipeline Tools" with a 401.

      PromoteForkPR.ps1        push branch + open a draft shadow PR -> PR-triggered ADO build
      ValidateForkPRBranch.ps1 push branch only                     -> CI-triggered ADO build

    This variant relies on the build being started against the validation branch directly, with no
    pull request in the middle. Azure DevOps reports a commit status whose context is the pipeline
    name, "WinUI-GitHub-PR (OneBranch)". Because the pushed commit is the IDENTICAL object as the
    fork PR head, that status lands on the fork PR and satisfies the required-check gate.

    This is proven end to end, not inferred: build 155987514 was queued against
    refs/heads/validation/fork-pr/11665/latest, came back with triggerInfo={} and a SUCCEEDED
    "Install Pipeline Tools" step, and posted "WinUI-GitHub-PR (OneBranch)" onto cd51237b — the head
    commit of fork PR 11665.

    Why this variant exists: the shadow-PR flow needs a "/azp run" comment to start the build
    (the definition sets isCommentRequiredForInternalRepoPRs = true), and when automation posts it
    the author is github-actions[bot], which Azure DevOps is unlikely to accept as a team member.
    This flow avoids that problem entirely — and produces no shadow PR to review, ignore, or
    accidentally merge.

    TWO WAYS TO START THE BUILD after the branch is pushed:

      -QueueBuild   Queue it explicitly through the Azure DevOps REST API. Works today with no
                    pipeline change, using the caller's own 'az login'. Best for running by hand.
                    In automation this needs a service principal.

      CI trigger    Let the push itself start the build. Requires a one-time definition change and
                    no Azure DevOps credential at all, which is what makes it the right choice for
                    the GitHub Actions workflow. Add it in the pipeline UI ("Triggers" >
                    "Continuous integration" > "Override the YAML continuous integration trigger
                    from here") with a branch filter of validation/*, NOT in
                    build/WinUI-GitHub-PR.yml. The UI-defined trigger overrides the YAML, so a fork
                    cannot disable its own validation by editing `trigger:` in its commit.
                    Use -CheckTrigger to see whether it is configured.

    If neither is used, the branch is pushed and nothing happens — no build, no status, and the
    fork PR simply stays blocked. -Publish warns when it detects this.

    SECURITY: publishing causes the fork's code, scripts, MSBuild targets and pipeline YAML to run
    in a CREDENTIALED pipeline. Only publish a commit AFTER reviewing that exact SHA. -Publish
    requires -IReviewedTheSha.

    KNOWN, UNFIXED BY THIS SCRIPT: Azure DevOps compiles the pipeline YAML from the commit being
    built, so the fork's copy of build/WinUI-GitHub-PR.yml shapes the credentialed run. Step bodies
    still come from internal repos pinned to refs/heads/main, so a fork cannot author build steps,
    but it can alter the extends target, resource pins, parameters and container image. Moving the
    definition to a protected control repository is the fix; unlike the shadow-PR flow, this flow
    stays compatible with that change because reporting does not depend on the PR trigger.

.PARAMETER PrNumber   Fork PR number (required).
.PARAMETER Repo       owner/name. Default microsoft/microsoft-ui-xaml.
.PARAMETER Remote     Local git remote pointing at upstream. Default origin.
.PARAMETER Publish    Push the fork's exact head commit to the validation branch.
.PARAMETER Status     Show the current validation result for the fork PR head SHA.
.PARAMETER Cleanup    Delete every validation branch for this fork PR.
.PARAMETER Invalidate Tear down a stale validation after a new fork commit and prompt for re-run.
.PARAMETER NewSha     New fork head SHA, referenced in the -Invalidate prompt (optional).
.PARAMETER IReviewedTheSha  Required acknowledgement for -Publish.
.PARAMETER ReuseBranch      Reuse one stable branch per fork PR (force-updated to each new SHA).
.PARAMETER Wait             Poll until the validation result leaves the pending state.
.PARAMETER QueueBuild       After pushing, queue the ADO build via REST (needs az login / an SP).
.PARAMETER CheckTrigger     Report whether the ADO definition has a CI trigger covering validation/*.

.EXAMPLE
    # Publish the reviewed head, queue the build, and block until the check resolves.
    # This is the by-hand path and needs no pipeline change:
    .\ValidateForkPRBranch.ps1 -PrNumber 11637 -Publish -IReviewedTheSha -QueueBuild -Wait
.EXAMPLE
    # Publish only; relies on a CI trigger on validation/* to start the build:
    .\ValidateForkPRBranch.ps1 -PrNumber 11637 -Publish -IReviewedTheSha
.EXAMPLE
    # One stable branch per fork PR, force-updated on each re-validation:
    .\ValidateForkPRBranch.ps1 -PrNumber 11637 -Publish -IReviewedTheSha -QueueBuild -ReuseBranch
.EXAMPLE
    .\ValidateForkPRBranch.ps1 -PrNumber 11637 -Status -Wait
.EXAMPLE
    .\ValidateForkPRBranch.ps1 -PrNumber 11637 -Cleanup
.EXAMPLE
    # See which start mechanism is available (needs az CLI + ADO access):
    .\ValidateForkPRBranch.ps1 -PrNumber 0 -CheckTrigger
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][int]$PrNumber,
    [string]$Repo   = 'microsoft/microsoft-ui-xaml',
    [string]$Remote = 'origin',
    [switch]$Publish,
    [switch]$Status,
    [switch]$Cleanup,
    # Tear down a now-stale validation after the fork pushed a NEW commit, and prompt maintainers to
    # re-review and re-run. We NEVER auto-publish the new commit: publishing runs fork code in a
    # credentialed pipeline, so every new SHA needs a fresh review.
    [switch]$Invalidate,
    [string]$NewSha,
    [switch]$IReviewedTheSha,
    [switch]$IReviewedTheBuildSurface,
    # Reuse ONE stable branch per fork PR (force-updated to each new SHA) instead of creating a
    # fresh SHA-suffixed branch on every push. Reduces branch sprawl and orphans.
    [switch]$ReuseBranch,
    [switch]$Wait,
    [int]$TimeoutMinutes = 90,
    [switch]$CheckTrigger,
    [switch]$QueueBuild,
    # ADO coordinates, used by -CheckTrigger and -QueueBuild.
    [string]$AdoOrgUrl        = 'https://dev.azure.com/microsoft',
    [string]$AdoProject       = 'WinUI',
    [int]$AdoDefinitionId     = 195405
)

$ErrorActionPreference = 'Stop'

# The required status/check context in ruleset 1069940. Azure DevOps uses the pipeline's name as the
# status context, so a CI build of definition 195405 reports under exactly this string.
$Context = 'WinUI-GitHub-PR (OneBranch)'

# All validation refs for a PR live under this directory so per-SHA branches and the stable
# -ReuseBranch head never collide in git's ref store. The trailing slash matters: without it,
# prefix queries for PR 11665 would also match 116650, 116651, ...
function Get-BranchPrefix { "validation/fork-pr/$PrNumber/" }

# Paths that influence HOW the build runs rather than what it produces. A change here is materially
# more dangerous than a change to product code: it can alter the pipeline's own instructions, which
# ADO compiles from the candidate commit (see the SECURITY note in the header). These are surfaced
# separately at publish time so they cannot be lost in a large diff.
#
# Directory prefixes: everything beneath them is build orchestration.
$script:BuildSurfaceDirs = @(
    'build/'
    'eng/'
    '.pipelines/'
    '.github/'
    '.azuredevops/'
    '.config/'
)
# Extensions that execute during a build NO MATTER WHERE THEY LIVE. MSBuild .props/.targets can run
# arbitrary tasks, so a nested one in the product tree is just as dangerous as a root one; the tree
# has ~240 of them, but only those the PR actually touches are ever reported.
$script:BuildSurfaceExts = @('.yml', '.yaml', '.props', '.targets', '.proj')
# Exact root-level filenames that steer restore/build tooling.
$script:BuildSurfaceFiles = @(
    'nuget.config', 'global.json', 'directory.build.props', 'directory.build.targets',
    'directory.packages.props', 'directory.build.rsp', 'dotnet-tools.json'
)

function Test-IsBuildSurface([string]$Path) {
    $p = $Path.Replace('\', '/')
    foreach ($d in $script:BuildSurfaceDirs) { if ($p.ToLowerInvariant().StartsWith($d)) { return $true } }
    foreach ($e in $script:BuildSurfaceExts) { if ($p.ToLowerInvariant().EndsWith($e)) { return $true } }
    $leaf = ($p -split '/')[-1]
    if ($script:BuildSurfaceFiles -contains $leaf.ToLowerInvariant()) { return $true }
    return $false
}

function Get-BuildSurfaceChanges {
    # Files the fork PR touches that fall on the build surface. Uses the PR's own file list, so it is
    # already scoped to the merge base — no local diff arithmetic to get wrong.
    $files = gh api "repos/$Repo/pulls/$PrNumber/files" --paginate --jq '.[].filename' 2>$null
    return @($files | Where-Object { $_ -and (Test-IsBuildSurface $_) })
}

function Assert-BuildSurfaceReviewed {
    $hits = @(Get-BuildSurfaceChanges)
    if (-not $hits) { return }

    Write-Host ""
    Write-Warning "This fork PR changes $($hits.Count) file(s) that control HOW the build runs:"
    foreach ($h in $hits) { Write-Host "    $h" }
    Write-Host ""
    Write-Host "These files are compiled and executed by a CREDENTIALED pipeline. Review them line by"
    Write-Host "line before publishing — a single line here outweighs any amount of product code."
    Write-Host ""

    # Print the patches inline so the decision is made with the change in view, not from a filename.
    # Emit one compact JSON object per line (@json) so the embedded newlines in .patch survive the
    # trip through the pipeline; iterating raw --jq text would split each patch into separate items.
    $rows = gh api "repos/$Repo/pulls/$PrNumber/files" --paginate --jq '.[] | @json' 2>$null
    foreach ($r in @($rows | Where-Object { $_ })) {
        $o = $null
        try { $o = $r | ConvertFrom-Json } catch { continue }
        if ($hits -notcontains $o.filename) { continue }
        Write-Host "=== $($o.filename) ===" -ForegroundColor Yellow
        if ($o.patch) {
            Write-Host $o.patch
        } else {
            # No patch means binary or too large to diff — that is MORE reason to look, not less.
            Write-Warning "  No inline diff available (binary or oversized). Inspect it manually:"
            Write-Host   "  $($o.blob_url)"
        }
        Write-Host ""
    }

    if (-not $IReviewedTheBuildSurface) {
        throw "Refusing to publish: pass -IReviewedTheBuildSurface to confirm you read the pipeline/build changes listed above."
    }
    Write-Warning "Proceeding: -IReviewedTheBuildSurface was supplied."
}

function Get-PrInfo {
    $json = gh pr view $PrNumber --repo $Repo --json headRefOid,baseRefName,isCrossRepository,state,url
    if ($LASTEXITCODE -ne 0) { throw "gh pr view failed for #$PrNumber" }
    $json | ConvertFrom-Json
}

# Read the validation result for a SHA from BOTH reporting mechanisms.
#
# Azure DevOps reports through a GitHub service connection, and which mechanism it uses depends on
# how that connection is configured: a personal OAuth grant posts legacy COMMIT STATUSES, while an
# Azure Pipelines GitHub App connection posts CHECK RUNS. Definition 195405 has already switched
# between the two once (2026-08-27 to 2026-08-31), so reading only one silently reports "none" for
# the entire window the other is in use. Always merge both.
function Get-ValidationState([string]$Sha) {
    $results = @()

    $statusJson = gh api "repos/$Repo/commits/$Sha/status" --jq ".statuses[] | select(.context==`"$Context`")" 2>$null
    foreach ($line in @($statusJson | Where-Object { $_ })) {
        $s = $line | ConvertFrom-Json
        $results += [pscustomobject]@{
            Kind = 'status'; State = $s.state; Description = $s.description
            Url = $s.target_url; Updated = $s.updated_at
        }
    }

    $checkJson = gh api "repos/$Repo/commits/$Sha/check-runs?per_page=100" --jq ".check_runs[] | select(.name==`"$Context`")" 2>$null
    foreach ($line in @($checkJson | Where-Object { $_ })) {
        $c = $line | ConvertFrom-Json
        # Normalise check-run vocabulary onto commit-status vocabulary so callers compare one set of
        # values: an unfinished check run is 'pending'; a finished one reports its conclusion.
        $state = if ($c.status -ne 'completed') { 'pending' }
                 elseif ($c.conclusion -in 'success','failure') { $c.conclusion }
                 else { $c.conclusion }
        $results += [pscustomobject]@{
            Kind = 'check_run'; State = $state; Description = $c.output.title
            Url = $c.html_url; Updated = $c.completed_at
        }
    }

    # Newest first, so the caller sees the most recent result when both mechanisms left a record.
    $results | Sort-Object { if ($_.Updated) { [datetime]$_.Updated } else { [datetime]::MinValue } } -Descending
}

function Wait-Validation([string]$Sha) {
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    do {
        $all   = @(Get-ValidationState $Sha)
        $cur   = $all | Select-Object -First 1
        $state = if ($cur) { $cur.State } else { 'none' }
        Write-Host ("[{0:HH:mm:ss}] {1} -> {2}  {3}" -f (Get-Date), $Context, $state, $cur.Description)
        if ($state -in 'success','failure','error','timed_out','cancelled','action_required') { return $cur }
        Start-Sleep -Seconds 30
    } while ((Get-Date) -lt $deadline)
    Write-Warning "Timed out after $TimeoutMinutes min; validation still '$state'."
    return $cur
}

# Verify which start mechanism is available. Without a CI trigger covering validation/* AND without
# -QueueBuild, pushing the branch is silent — no build, no status, and the fork PR simply stays
# blocked with no diagnostic.
function Get-AdoToken {
    $token = az account get-access-token --resource '499b84ac-1321-427f-aa17-267ca6975798' --query accessToken -o tsv
    if ($LASTEXITCODE -ne 0 -or -not $token) { throw "az account get-access-token failed; run 'az login' first." }
    return $token.Trim()
}

# Queue the pipeline directly against the validation branch. This is the no-pipeline-change path:
# a manually queued build on a non-fork ref gets full credentials (triggerInfo is empty) and still
# reports the pipeline-name commit status onto the built SHA — proven by build 155987514.
function Invoke-QueueBuild([string]$Sha, [string]$Branch) {
    $body = @{
        definition    = @{ id = $AdoDefinitionId }
        sourceBranch  = "refs/heads/$Branch"
        sourceVersion = $Sha
    } | ConvertTo-Json -Depth 5
    $uri = "$AdoOrgUrl/$AdoProject/_apis/build/builds?api-version=7.1"
    try {
        $build = Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType 'application/json' `
                                   -Headers @{ Authorization = "Bearer $(Get-AdoToken)" }
    } catch {
        # ADO rejects at queue time if the candidate commit's YAML fails to compile, which is a
        # genuine result about the fork's change, not a script failure — surface it verbatim.
        $detail = $_.ErrorDetails.Message
        throw "Queueing build failed: $(if ($detail) { $detail } else { $_.Exception.Message })"
    }
    Write-Host "Queued build $($build.id): $($build._links.web.href)"
    return $build
}

if ($CheckTrigger) {
    $uri = "$AdoOrgUrl/$AdoProject/_apis/build/definitions/$AdoDefinitionId`?api-version=7.1"
    $def = Invoke-RestMethod -Uri $uri -Headers @{ Authorization = "Bearer $(Get-AdoToken)" }
    Write-Host "Definition $AdoDefinitionId '$($def.name)' (revision $($def.revision))"
    $ci = @($def.triggers | Where-Object { $_.triggerType -eq 'continuousIntegration' })
    if (-not $ci) {
        Write-Warning "No continuousIntegration trigger. Pushing a validation branch will NOT build on its own."
        Write-Host  "Either add one in the pipeline UI (Triggers > Continuous integration > Override the YAML"
        Write-Host  "continuous integration trigger from here) with a branch filter of validation/*,"
        Write-Host  "or run -Publish with -QueueBuild, which needs no pipeline change."
        return
    }
    foreach ($t in $ci) {
        $filters = @($t.branchFilters)
        Write-Host "  continuousIntegration branchFilters: $($filters -join ', ')"
        # A UI-defined trigger has no settingsSourceType; one sourced from YAML reports 2. Only the
        # UI-defined form overrides the candidate commit's own `trigger:` block.
        if ($t.PSObject.Properties.Name -contains 'settingsSourceType' -and $t.settingsSourceType -eq 2) {
            Write-Warning "  This trigger comes from YAML, so a fork can disable it by editing 'trigger:'. Use the UI override instead."
        }
        $covers = $filters | Where-Object { $_ -match 'validation' -or $_ -eq '+refs/heads/*' -or $_ -eq '*' }
        if ($covers) { Write-Host "  OK: validation/* appears covered." }
        else { Write-Warning "  Filters do not appear to cover validation/*; branch pushes will not build." }
    }
    return
}

$info = Get-PrInfo
$Sha  = $info.headRefOid
$Base = $info.baseRefName

$prefix = Get-BranchPrefix
$Branch = if ($ReuseBranch) { "${prefix}latest" } else { "$prefix$($Sha.Substring(0,8))" }

if ($Status) {
    Write-Host "Fork PR #$PrNumber  head=$Sha  base=$Base  state=$($info.state)"
    if ($Wait) { Wait-Validation $Sha; return }
    $all = @(Get-ValidationState $Sha)
    if ($all) { $all } else { Write-Host "No '$Context' status or check run on $Sha yet." }
    return
}

function Invoke-BranchCleanup {
    # Delete EVERY validation ref for this fork PR, not just the current branch: re-validations can
    # leave orphaned per-SHA branches behind.
    $p = Get-BranchPrefix
    $refs = gh api "repos/$Repo/git/matching-refs/heads/$p" --jq '.[].ref' 2>$null
    $refs = @($refs | Where-Object { $_ })
    if (-not $refs) { Write-Host "Nothing to clean for $p."; return 0 }

    # Defensive: this flow opens no PRs, but PromoteForkPR.ps1 targets the same namespace. Closing
    # someone else's shadow PR is not this script's job, so warn rather than delete silently.
    $openPrs = gh pr list --repo $Repo --search "head:validation/fork-pr/$PrNumber" --state open `
                 --json number,headRefName 2>$null | ConvertFrom-Json
    foreach ($pr in @($openPrs | Where-Object { $_.headRefName -like "$p*" })) {
        Write-Warning "Branch $($pr.headRefName) has open PR #$($pr.number) (likely from PromoteForkPR.ps1). Deleting the branch will close it."
    }

    foreach ($ref in $refs) {
        $b = $ref -replace '^refs/heads/', ''
        Write-Host "Deleting branch $b"
        git push $Remote --delete "refs/heads/$b" 2>$null
    }
    return $refs.Count
}

if ($Cleanup) { [void](Invoke-BranchCleanup); return }

if ($Invalidate) {
    # A new commit landed on the fork PR, so the validated SHA is no longer the head. Remove the
    # validation branches and tell maintainers a fresh review is needed.
    #
    # Note on mechanism: deleting the branch does NOT retract the status already posted on the OLD
    # SHA — statuses and check runs are immutable records on the commit they were written to. The
    # merge gate re-blocks because the PR's NEW head SHA has no validation result of its own.
    # Removing the branch matters for hygiene and to stop a stale build reporting late.
    $removed = Invoke-BranchCleanup
    if ($removed -gt 0) {
        $short = if ($NewSha) { $NewSha.Substring(0, [Math]::Min(8, $NewSha.Length)) } else { '' }
        $tmpl = @'
⚠️ A new commit (`__SHA__`) was pushed to this fork PR, so the previous validation no longer applies to the current head. Its validation branch was removed and the **WinUI-GitHub-PR (OneBranch)** check is outstanding again.

A maintainer must review the new code and comment `/validate` (optionally `/validate __SHA__`) to validate this commit. For security, new commits on fork PRs are never validated automatically.
'@
        $body = $tmpl -replace '__SHA__', $short
        Write-Host "Posting stale-validation notice on fork PR #$PrNumber ..."
        $body | gh pr comment $PrNumber --repo $Repo --body-file -
    } else {
        Write-Host "No validation artifacts to invalidate for fork PR #$PrNumber."
    }
    return
}

if ($Publish) {
    if (-not $info.isCrossRepository) { throw "PR #$PrNumber is not a fork; no validation branch needed." }
    if (-not $IReviewedTheSha) {
        throw "Refusing to publish: pass -IReviewedTheSha to confirm you reviewed exact SHA $Sha. " +
              "Publishing runs the fork's code in a credentialed pipeline."
    }

    # Surface build-instruction changes BEFORE anything is published. This is the step that stops a
    # one-line pipeline edit disappearing into a large product diff.
    Assert-BuildSurfaceReviewed

    Write-Host "Fetching pull/$PrNumber/head ..."
    git fetch --no-tags $Remote "pull/$PrNumber/head"
    if ($LASTEXITCODE -ne 0) { throw "git fetch of pull/$PrNumber/head failed (exit $LASTEXITCODE)." }
    $fetched = (git rev-parse FETCH_HEAD).Trim()
    if ($fetched -ne $Sha) { throw "Fetched SHA ($fetched) != PR head SHA ($Sha); aborting." }

    # TOCTOU guard: re-read the PR head immediately before pushing so we never publish a commit the
    # maintainer did not review, if the fork advanced while we were fetching.
    $now = (Get-PrInfo).headRefOid
    if ($now -ne $Sha) {
        throw "PR head changed ($Sha -> $now) since start; re-run to validate the new SHA."
    }

    # Push the IDENTICAL commit object — never a cherry-pick, rebase or merge. The shared SHA is the
    # entire mechanism: it is what makes the resulting status appear on the fork PR.
    # -ReuseBranch force-updates the stable branch (a forced update still fires the CI trigger);
    # per-SHA branches never move, so the leading '+' is harmless there.
    Write-Host "Pushing identical commit to $Branch ..."
    git push $Remote "+$Sha`:refs/heads/$Branch"
    if ($LASTEXITCODE -ne 0) {
        throw "git push to $Branch failed (exit $LASTEXITCODE). A likely cause is a ref name " +
              "conflict with an existing validation branch for this PR; run -Cleanup and retry."
    }

    $upstream = (gh api "repos/$Repo/git/ref/heads/$Branch" --jq '.object.sha').Trim()
    if ($upstream -ne $Sha) { throw "Upstream branch SHA ($upstream) != $Sha; aborting." }

    Write-Host ""
    Write-Host "Published $Sha to $Branch."

    if ($QueueBuild) {
        Write-Host "Queueing build against $Branch ..."
        [void](Invoke-QueueBuild -Sha $Sha -Branch $Branch)
    } else {
        Write-Host "Relying on the CI trigger on validation/* to start the build."
        Write-Host "If that trigger is not configured, nothing will run — check with -CheckTrigger,"
        Write-Host "or re-run with -QueueBuild to start it explicitly."
    }

    Write-Host ""
    Write-Host "Azure DevOps reports '$Context' against $Sha, which is also this fork PR's head,"
    Write-Host "so the check lands on the PR. No shadow PR and no '/azp run' comment are involved."
    Write-Host ""

    if ($Wait) { Wait-Validation $Sha }
    else { Write-Host "Watch: .\ValidateForkPRBranch.ps1 -PrNumber $PrNumber -Status -Wait" }
    return
}

Write-Host "Nothing to do. Specify -Publish, -Status, -Cleanup, -Invalidate, or -CheckTrigger. (-Publish needs -IReviewedTheSha)"
