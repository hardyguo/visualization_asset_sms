/*
Navicat MySQL Data Transfer

Source Server         : topo
Source Server Version : 50544
Source Host           : 10.65.60.11:3306
Source Database       : assets_scan

Target Server Type    : MYSQL
Target Server Version : 50544
File Encoding         : 65001

Date: 2016-09-06 11:16:13
*/

SET FOREIGN_KEY_CHECKS=0;
-- ----------------------------
-- Table structure for `asset`
-- ----------------------------
DROP TABLE IF EXISTS `asset`;
CREATE TABLE `asset` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT 'id',
  `numbering` varchar(64) NOT NULL COMMENT '资产编号',
  `name` varchar(64) NOT NULL COMMENT '资产名称',
  `ip` varchar(64) DEFAULT NULL COMMENT 'ip地址',
  `mask` varchar(32) DEFAULT NULL COMMENT '掩码',
  `hostname` varchar(256) DEFAULT NULL COMMENT '主机名称',
  `macascii` varchar(32) DEFAULT NULL COMMENT 'MAC地址',
  `macvendor` varchar(32) DEFAULT NULL COMMENT 'MAC厂商',
  `os_type` varchar(128) DEFAULT NULL COMMENT '操作系统类型',
  `os_detail` varchar(128) DEFAULT NULL COMMENT '操作系统详情',
  `type` int(11) DEFAULT NULL COMMENT '资产类型',
  `vendor` varchar(256) DEFAULT NULL COMMENT '设备厂商',
  `create_time` datetime DEFAULT NULL COMMENT '添加时间',
  `zone` int(11) DEFAULT NULL COMMENT '区域',
  `desc` text COMMENT '描述',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of asset
-- ----------------------------

-- ----------------------------
-- Table structure for `asset_type`
-- ----------------------------
DROP TABLE IF EXISTS `asset_type`;
CREATE TABLE `asset_type` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT 'id',
  `name` varchar(32) DEFAULT NULL COMMENT '资产类型',
  `desc` text COMMENT '描述',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of asset_type
-- ----------------------------
INSERT INTO `asset_type` VALUES ('1', '主机', '');
INSERT INTO `asset_type` VALUES ('2', '服务器', '');
INSERT INTO `asset_type` VALUES ('3', '集线器', '');
INSERT INTO `asset_type` VALUES ('4', '传真机', '');
INSERT INTO `asset_type` VALUES ('5', '二层交换机', '');
INSERT INTO `asset_type` VALUES ('6', '三层交换机', '');
INSERT INTO `asset_type` VALUES ('7', '路由器', '');
INSERT INTO `asset_type` VALUES ('8', '防火墙', '');
INSERT INTO `asset_type` VALUES ('9', '无线路由器', '');
INSERT INTO `asset_type` VALUES ('99', '未知设备', '');

-- ----------------------------
-- Table structure for `assets_port_service`
-- ----------------------------
DROP TABLE IF EXISTS `assets_port_service`;
CREATE TABLE `assets_port_service` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT 'id',
  `port` int(11) DEFAULT NULL COMMENT '端口号',
  `protocol` varchar(32) DEFAULT NULL COMMENT '协议类型',
  `status` varchar(32) DEFAULT NULL COMMENT '端口状态',
  `service` varchar(128) DEFAULT NULL COMMENT '服务名称',
  `version` varchar(256) DEFAULT NULL COMMENT '服务版本',
  `ip` varchar(64) DEFAULT NULL COMMENT 'ip地址',
  `create_time` datetime DEFAULT NULL COMMENT '添加时间',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of assets_port_service
-- ----------------------------

-- ----------------------------
-- Table structure for `topo_config`
-- ----------------------------
DROP TABLE IF EXISTS `topo_config`;
CREATE TABLE `topo_config` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT 'id',
  `name` varchar(128) DEFAULT NULL COMMENT '名称',
  `core_ip` varchar(32) DEFAULT NULL COMMENT '核心IP',
  `layers` int(11) DEFAULT '8' COMMENT '扫描层级',
  `snmp_timeout` int(11) DEFAULT '5' COMMENT 'SNMP超时时间(s)',
  `icmp_timeout` int(11) DEFAULT '5' COMMENT 'ICMP超时时间(s)',
  `filter_subnet` varchar(128) DEFAULT NULL COMMENT '过滤子网',
  `snmp_retries` int(1) DEFAULT '1' COMMENT 'SNMP重试次数',
  `max_thread` int(3) DEFAULT NULL COMMENT '最大线程数',
  `start_time` int(11) DEFAULT NULL COMMENT '开始时间',
  `end_time` int(11) DEFAULT NULL COMMENT '结束时间',
  `timeout` int(11) DEFAULT NULL COMMENT '扫描超时时间(s)',
  `scan_result` int(11) DEFAULT NULL COMMENT '扫描结果',
  `synchronize_asset` int(11) NOT NULL DEFAULT '1' COMMENT '是否同步资产数据',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of topo_config
-- ----------------------------

-- ----------------------------
-- Table structure for `topo_config_snmp`
-- ----------------------------
DROP TABLE IF EXISTS `topo_config_snmp`;
CREATE TABLE `nm_monitor_argument` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ip` varchar(64) DEFAULT NULL,
  `snmp_port` int(11) DEFAULT '161' COMMENT 'SNMP端口',
  `snmp_version` int(11) DEFAULT '2' COMMENT 'SNMP版本',
  --V1/2c参数：
  `read_key` varchar(128) DEFAULT 'public' COMMENT '读关键字',
  `write_key` varchar(128) DEFAULT 'private' COMMENT '写关键字',
  --V3参数：
  `security_level` int(11) DEFAULT NULL COMMENT 'security level (noAuthNoPriv|authNoPriv|authPriv)',
  `auth_protocol` varchar(32) DEFAULT NULL COMMENT 'authentication protocol (MD5|SHA)',
  `auth_pass` varchar(32) DEFAULT NULL COMMENT 'authentication protocol pass phrase',
  `user_name` varchar(32) DEFAULT NULL COMMENT 'security name (e.g. bert)',
  `privacy_protocol` varchar(32) DEFAULT NULL COMMENT 'privacy protocol (DES|AES)',
  `privacy_pass` varchar(32) DEFAULT NULL COMMENT 'privacy protocol pass phrase',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of topo_config_snmp
-- ----------------------------

-- ----------------------------
-- Table structure for `topo_relation`
-- ----------------------------
DROP TABLE IF EXISTS `topo_relation`;
CREATE TABLE `topo_relation` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT 'id',
  `ip` varchar(32) DEFAULT NULL COMMENT 'ip地址',
  `layer` int(11) DEFAULT NULL COMMENT '发现层级',
  `parent_ip` varchar(32) DEFAULT NULL COMMENT '父节点ip地址',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of topo_relation
-- ----------------------------

-- ----------------------------
-- Table structure for `user`
-- ----------------------------
DROP TABLE IF EXISTS `user`;
CREATE TABLE `user` (
  `user_id` varchar(32) NOT NULL COMMENT '用户id',
  `user_name` varchar(32) NOT NULL COMMENT '用户名称',
  `user_passwd` varchar(32) NOT NULL COMMENT '用户密码',
  `user_mail` varchar(64) DEFAULT NULL COMMENT '用户邮箱',
  `user_tel` varchar(16) DEFAULT NULL COMMENT '用户电话',
  `user_enable` int(2) DEFAULT NULL COMMENT '是否可用',
  PRIMARY KEY (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of user
-- ----------------------------
INSERT INTO `user` VALUES ('1', 'admin', '2f780b5a7762af9c258076e913178715', 'assetsview@sina.cn', '13312345678', '1');
