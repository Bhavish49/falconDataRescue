Controlled falconDataRescue image-recovery fixtures

synthetic_car_damaged.jpg: Recoverable prefix plus missing JPEG EOI
recoverable_missing_eoi.jpg: Recoverable missing JPEG EOI
recoverable_truncated_scan.jpg: Truncated JPEG scan; may produce partial output
recoverable_prefix_only.jpg: Recoverable JPEG with harmless leading bytes
pixel_corrupted_valid_jpeg.jpg: Valid JPEG with intentionally damaged pixels; exact pixels are unavailable
uniform_black_valid_jpeg.jpg: Valid but visually uniform image; must not be called a scene recovery
invalid_jpeg_bytes.jpg: Invalid JPEG bytes; must be rejected

Upload several files together to test batch behavior.
