# patchorder and the Windows Autopatch approval model

patchorder tells you *which* Windows build fixes a CVE on *which* inventory rows, for example:

```text
Patch Windows 11 23H2 10.0.22631.3593 on 15 internal hosts (owner it). Highest issue: CVE-2024-38063. Update to 10.0.22631.4037 or later (NVD versionEndExcluding). Priority 43.25.
```

It does not deploy anything and does not talk to Intune or Windows Autopatch. If your Windows devices get their updates through Windows Autopatch, this page explains where a patchorder finding meets the Autopatch approval settings. Everything about Autopatch below is taken from the Microsoft sources listed at the end (checked on 2026-11-17); the "what to do with a finding" column is patchorder's suggestion, not Microsoft guidance.

## How Autopatch decides when an update reaches a device

Windows Autopatch quality update policies in Intune let you choose an approval method per update type [1][2]:

| Update type (quality update policy) | Default approval | Notes |
| --- | --- | --- |
| Monthly security updates (Windows cumulative update and .NET Framework security update, usually second Tuesday) | Automatic | Offered after the policy's deferral ("Make updates available after", 0 to 30 days). Microsoft recommends keeping quality update deferrals under three days [1]. |
| Monthly non-security preview updates (usually fourth week) | Manual | Offered only after an admin approves the release for a policy [1]. |
| Out-of-band (OOB) security updates | Manual | Same approval flow as above [1]. |
| Out-of-band non-security updates | Manual | Same approval flow as above [1]. |

Details that matter when you act on a finding:

- **Automatic approval:** devices get the update after the policy's deferral. That deferral *replaces* the update ring or Autopatch group deferral, it is not added to it: a 5-day ring deferral and a 2-day policy deferral mean the update arrives 2 days after release [2]. Deadlines and grace periods from the update ring or Autopatch group still apply [2].
- **Manual approval:** no deferral. Devices get the update once you approve it, in Intune under *Devices > Manage updates > Windows updates > Quality updates > Manage updates*. Policies that are not approved yet show as *Needs review* for that release [1].
- **Expedite:** a targeted policy can expedite a specific quality update to the tenant [1].
- **Pause:** pausing an approved update revokes its approval, so no new devices receive it. Devices that already installed it are not rolled back. Re-approving resumes the rollout [1].
- **Drivers and firmware** have their own Automatic/Manual mode per Autopatch group or deployment ring. In Manual mode no driver is installed without explicit approval. Switching modes generates new policies and drops earlier approvals, pauses and declines [3].

## What to do with a patchorder finding

| patchorder finding | Autopatch release type it usually maps to | Suggested action |
| --- | --- | --- |
| Windows row, fixed build is in a monthly security update, not in KEV | Monthly security update (automatic) | Nothing to approve. Check that the policy deferral plus the ring deadline gets the hosts to the fixed build in time. |
| Windows row with a KEV finding (`kev_due_date` set) | Monthly security update (automatic) | Compare the deferral and deadline with `kev_due_date`. If the update would land after the due date, expedite it [1] instead of shortening the deferral for everything. |
| Fixed build only in an out-of-band security release | OOB security update (manual by default) | Approve the release for the affected policies [1]; it is not offered until then. |
| Fixed build only in a non-security preview update | Monthly non-security preview (manual by default) | Decide on purpose. Until it is approved, the hosts stay on the affected build. |
| Rollout was paused | Any | patchorder keeps reporting the rows as affected. Pausing does not roll back devices that already updated [1]; re-run patchorder after re-approval. |

patchorder only knows the build you wrote in the inventory. Update the `version` column from your device inventory after a rollout, then run the briefing again to confirm the rows moved out of the affected range.

## Sources

1. Microsoft Learn, *Windows quality updates and .NET Framework updates* (Windows Autopatch), last updated 2026-10-20: <https://learn.microsoft.com/en-us/windows/deployment/windows-autopatch/manage/windows-autopatch-windows-quality-update-overview>
2. Windows IT Pro Blog, *Granular controls for multiple updates in Windows Autopatch*, 12 Nov 2026: <https://techcommunity.microsoft.com/blog/windows-itpro-blog/granular-controls-for-multiple-updates-in-windows-autopatch/4572668>
3. Microsoft Learn, *Manage driver and firmware updates* (Windows Autopatch): <https://learn.microsoft.com/en-us/windows/deployment/windows-autopatch/manage/windows-autopatch-manage-driver-and-firmware-updates>
