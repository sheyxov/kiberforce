#!/usr/bin/env python3
import argparse
import logging
import sys
from pathlib import Path

from detector import Detector, DetectionError
from crackers import CrackerFactory, CrackerError


def setup_logging(verbose: bool) -> None:
    """Configure logging based on verbosity level."""
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    )


def validate_wordlist(filepath: str) -> Path:
    """Validate that wordlist file exists."""
    path = Path(filepath)
    if not path.exists():
        raise argparse.ArgumentTypeError(f"Wordlist file not found: {filepath}")
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"Not a file: {filepath}")
    return path


def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Professional crack detection and cracking CLI tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Detect and crack an MD5 hash using rockyou.txt
  %(prog)s -i "5d41402abc4b2a76b9719d911017c592" -w rockyou.txt

  # Detect cipher type and attempt auto-decryption
  %(prog)s -i "SGVsbG8gV29ybGQ="

  # Use specific algorithm and 8 worker processes
  %(prog)s -i "<hash>" -w wordlist.txt -a sha256 --workers 8

  # Verbose output for debugging
  %(prog)s -i "<hash>" -w wordlist.txt -v
        """,
    )

    parser.add_argument(
        '-i', '--input',
        type=str,
        required=True,
        help='The string to analyze (hash or cipher)',
    )

    parser.add_argument(
        '-w', '--wordlist',
        type=validate_wordlist,
        help='Path to wordlist file for hash cracking (required for hash cracking)',
    )

    parser.add_argument(
        '-a', '--algorithm',
        type=str,
        help='Specific algorithm to use (md5, sha1, sha256, sha512, etc.)',
    )

    parser.add_argument(
        '--workers',
        type=int,
        default=4,
        help='Number of worker processes for hash cracking (default: 4)',
    )

    parser.add_argument(
        '--chunk-size',
        type=int,
        default=1000,
        help='Words per chunk for multiprocessing (default: 1000)',
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging output',
    )

    parser.add_argument(
        '--force-hash',
        action='store_true',
        help='Force input to be treated as a hash (skip cipher detection)',
    )

    parser.add_argument(
        '--force-cipher',
        action='store_true',
        help='Force input to be treated as a cipher (skip hash detection)',
    )

    return parser


def print_detection_result(result) -> None:
    """Log detection result in a structured way."""
    logger = logging.getLogger('crackdetector.main')
    logger.info('DETECTION: type=%s category=%s algorithm=%s confidence=%.1f%%',
                result.detected_type,
                result.category,
                result.algorithm or 'N/A',
                result.confidence * 100.0)


def print_crack_result(result: str, input_string: str) -> None:
    """Log cracking result in a structured way."""
    logger = logging.getLogger('crackdetector.main')
    logger.info('CRACKED: input=%s output=%s', input_string, result)


def main() -> int:
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args()

    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    logger.info(f"Crack Detector - Professional CLI Tool")
    logger.info(f"Input: {args.input[:50]}..." if len(args.input) > 50 else f"Input: {args.input}")

    try:
        # Step 1: Detection
        logger.info("Step 1: Detecting input type...")

        if args.force_hash:
            # Skip detection, treat as hash
            detection_result = type('obj', (object,), {
                'detected_type': args.algorithm or 'md5',
                'category': 'hash',
                'confidence': 1.0,
                'algorithm': (args.algorithm or 'md5').upper(),
            })()
        elif args.force_cipher:
            # Skip detection, treat as cipher
            detection_result = type('obj', (object,), {
                'detected_type': 'unknown',
                'category': 'cipher',
                'confidence': 1.0,
                'algorithm': 'Auto',
            })()
        else:
            # Auto-detect
            detection_result = Detector.detect(args.input)

        print_detection_result(detection_result)

        if detection_result.category == 'unknown':
            logger.error("Could not determine input type. Use --force-hash or --force-cipher")
            return 1

        # Step 2: Cracking
        logger.info("Step 2: Attempting to crack %s...", detection_result.category)
        try:
            cracker = CrackerFactory.get_cracker(detection_result.category)
        except Exception as e:
            logger.error("No cracker available: %s", e)
            return 1

        if detection_result.category == 'hash':
            if not args.wordlist:
                logger.error("Wordlist required for hash cracking (-w/--wordlist)")
                return 1

            try:
                result = cracker.crack(
                    args.input,
                    hash_type=args.algorithm or detection_result.detected_type,
                    wordlist_path=str(args.wordlist),
                    num_workers=args.workers,
                    chunk_size=args.chunk_size,
                )
            except CrackerError as e:
                logger.error("Cracker error: %s", e)
                return 1

        elif detection_result.category == 'cipher':
            try:
                result = cracker.crack(
                    args.input,
                    cipher_type=detection_result.detected_type,
                )
            except CrackerError as e:
                logger.error("Cracker error: %s", e)
                return 1

        else:
            logger.error("Unknown category: %s", detection_result.category)
            return 1

        # Print results
        if result:
            print_crack_result(result, args.input)
            return 0
        else:
            logger.info("RESULT: Could not crack the input")
            logger.warning("Could not crack input. Try:")
            logger.warning("  - Different wordlist for hashes")
            logger.warning("  - Different cipher type")
            return 1

    except KeyboardInterrupt:
        logger.info("\nCracking interrupted by user")
        return 130
    except DetectionError as e:
        logger.error("Detection failed: %s", e)
        return 2
    except CrackerError as e:
        logger.error("Cracker failed: %s", e)
        return 3
    except ValueError as e:
        logger.error("Value error: %s", e)
        return 1
    except Exception as e:
        logger.error("Unexpected error: %s", e, exc_info=args.verbose)
        return 1


if __name__ == '__main__':
    sys.exit(main())
