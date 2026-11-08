## Assets (page "Assets", form, watchlist)

assets-areas = Asset sections
assets-tab-assets = Assets
assets-tab-watchlist = Watchlist
assets-search = Search assets
assets-search-placeholder = Search asset, package, version, host
assets-kind-any = All kinds
assets-open-only = only with open matches
assets-filter = Filter
assets-add = Add asset
assets-add-here = Add asset here
assets-none-title = No assets yet
assets-none-text = Add your software, packages and devices. Only advisories that fit them reach the inbox.
assets-none-filtered = No asset fits the filter.
assets-col-asset = Asset
assets-col-version = Version
assets-col-kind = Kind
assets-col-detail = Identifier / note
assets-col-open = Open matches
assets-toggle = Expand or collapse
assets-no-host = Without host
assets-group-count = { $count ->
    [one] 1 asset
   *[other] { $count } assets
}
assets-open-count = { $count } open
assets-group-open = { $count ->
    [one] 1 open vulnerability
   *[other] { $count } open vulnerabilities
}
assets-open-none = none
assets-shown = { $shown } of { $total } assets

asset-kind-package = Package (Debian/Ubuntu)
asset-kind-software = Software
asset-kind-hardware = Hardware / firmware
asset-new-title = Add asset
asset-back = Assets
asset-matched = Last matched
asset-kind = Kind
asset-kind-package-help = Packages are matched with the data of Debian and Ubuntu, software and devices with CVE, NVD and CSAF.
asset-fields-package = Package
asset-fields-product = Product
asset-distro = Distribution
asset-release = Release
asset-release-help = Debian: major version (12, 13), Ubuntu: year and month (24.04)
asset-pro = Ubuntu Pro (ESM) is active
asset-pro-help = Then the fixes of Ubuntu Pro count, where there are any.
asset-package = Package name
asset-package-help = Binary or source package as in dpkg, e.g. openssh-server
asset-vendor = Vendor
asset-vendor-help = Suggestions from CVE, NVD and CSAF data
asset-product = Product
asset-cpe = Identifier (CPE 2.3, optional)
asset-cpe-help = Fills in vendor, product and version where they are empty. Only give it if you know it.
asset-version = Version
asset-version-help = For packages the version as in dpkg (with epoch and revision), otherwise as the vendor writes it
asset-host = Host / device
asset-host-help = Groups the assets and is shown in the inbox
asset-note = Note
asset-preview-title = Preview of the matches
asset-preview-hint = Enter a product or package and its version to see which advisories fit right now.
asset-no-source-pi = no data source (Raspberry Pi kernel)
asset-no-source-pi-note = Raspberry Pi builds the kernel and firmware of Raspberry Pi OS itself. The data of Debian does not fit them, so opensecmon does not match this package. Their updates come through apt from Raspberry Pi.
asset-preview-none = No known advisory for these details at the moment.
asset-preview-count = { $count ->
    [one] Would currently match 1 advisory.
   *[other] Would currently match { $count } advisories.
}
asset-preview-more = and { $count } more
asset-save = Save
asset-preview = Preview
asset-cancel = Cancel
asset-delete = Delete asset
asset-delete-help = Deletes the asset with all its matches and their triage state.

asset-error-kind = Unknown kind.
asset-error-too-long = A field is too long.
asset-error-control = A field contains control characters.
asset-error-distro = Choose Debian or Ubuntu.
asset-error-release = The release does not fit: a number for Debian (13), year.month for Ubuntu (24.04).
asset-error-package = The package name does not fit (lower case letters, digits, + - . as in dpkg).
asset-error-package-version = The package version must start with a digit (e.g. 1:9.6p1-3ubuntu13.4).
asset-error-cpe = The identifier is not a valid CPE 2.3 (cpe:2.3:a:vendor:product:…).
asset-error-product = Enter a product (or a CPE).

watch-title = Watchlist
watch-text = Keywords for devices and programs without a clean identifier. They are searched in the titles and product data of the advisories. Their matches have the confidence
watch-none = No keywords yet.
watch-open = { $count } open
watch-since = since
watch-delete = Remove keyword
watch-keyword = Add keyword
watch-add = Add
watch-add-help = Whole words, case does not matter. New keywords look back 30 days.
watch-error-short = The keyword needs at least three letters or digits.
watch-error-exists = This keyword is already on the watchlist.

## Matches

match-confidence-high = high
match-confidence-medium = medium
match-confidence-low = low
match-method-distro = Distribution (package version)
match-method-nvd = NVD (CPE and version)
match-method-cna = CVE record (product and version)
match-method-csaf = Advisory (product tree)
match-method-watch = Watchlist keyword

flash-asset-added = Asset added and matched.
flash-asset-saved = Asset saved and matched again.
flash-asset-deleted = Asset deleted.
flash-watch-added = Keyword added and matched.
flash-watch-deleted = Keyword removed.
asset-min-prio = In the inbox from priority
asset-min-prio-help = Empty or 0: all matches. Matches below stay stored and show only with the filter on this asset, not in counts, situation and mails. Kernel packages from the SSH import start at 65.
asset-error-min-prio = The minimum priority must be a whole number from 0 to 100.
assets-min-prio-title = Matches below priority { $prio } are muted
