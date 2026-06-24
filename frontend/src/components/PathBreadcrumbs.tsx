import {
    Breadcrumb,
    BreadcrumbItem,
    BreadcrumbLink,
    BreadcrumbList,
    BreadcrumbPage,
    BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";

export function PathBreadcrumbs({
    crumbs,
    onNavigate,
    currentFile,
}: {
    crumbs: Array<{ label: string; path: string }>;
    onNavigate: (path: string) => void;
    currentFile?: string;
}) {
    return (
        <Breadcrumb>
            <BreadcrumbList>
                {crumbs.map((crumb, index) => {
                    const isLastDirectory = index === crumbs.length - 1;
                    const showAsPage = isLastDirectory && !currentFile;
                    const showSeparator =
                        !isLastDirectory || Boolean(currentFile);

                    return (
                        <div
                            key={crumb.path || "root"}
                            className="inline-flex items-center gap-1.5"
                        >
                            <BreadcrumbItem>
                                {showAsPage ? (
                                    <BreadcrumbPage className="inline-flex min-h-8 min-w-8 items-center justify-center rounded-md px-2">
                                        {crumb.label}
                                    </BreadcrumbPage>
                                ) : (
                                    <BreadcrumbLink asChild>
                                        <button
                                            type="button"
                                            className="hover:bg-muted inline-flex min-h-8 min-w-8 cursor-pointer items-center justify-center rounded-md px-2 focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"
                                            onClick={() =>
                                                onNavigate(crumb.path)
                                            }
                                        >
                                            {crumb.label}
                                        </button>
                                    </BreadcrumbLink>
                                )}
                            </BreadcrumbItem>
                            {showSeparator ? <BreadcrumbSeparator /> : null}
                        </div>
                    );
                })}
                {currentFile ? (
                    <BreadcrumbItem>
                        <BreadcrumbPage className="inline-flex min-h-8 min-w-8 items-center justify-center rounded-md px-2">
                            {currentFile}
                        </BreadcrumbPage>
                    </BreadcrumbItem>
                ) : null}
            </BreadcrumbList>
        </Breadcrumb>
    );
}
