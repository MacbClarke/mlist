import {
    FileIcon,
    FileMusicIcon,
    FilePlayIcon,
    FileTextIcon,
    FolderIcon,
    ImageIcon,
} from "lucide-react";

import type { ListEntry } from "@/types";
import {
    isAudioFile,
    isImageFile,
    isMarkdownFile,
    isPlainTextFile,
    isVideoFile,
} from "@/lib/fileTypes";

export function EntryIcon({ entry }: { entry: ListEntry }) {
    if (entry.kind === "dir")
        return <FolderIcon className="text-muted-foreground size-4 shrink-0" />;
    if (isMarkdownFile(entry) || isPlainTextFile(entry))
        return (
            <FileTextIcon className="text-muted-foreground size-4 shrink-0" />
        );
    if (isImageFile(entry))
        return <ImageIcon className="text-muted-foreground size-4 shrink-0" />;
    if (isAudioFile(entry))
        return (
            <FileMusicIcon className="text-muted-foreground size-4 shrink-0" />
        );
    if (isVideoFile(entry))
        return (
            <FilePlayIcon className="text-muted-foreground size-4 shrink-0" />
        );
    return <FileIcon className="text-muted-foreground size-4 shrink-0" />;
}
